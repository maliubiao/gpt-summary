Response: My thinking process to analyze the provided C++ unittest file for the Chromium Blink engine involved these steps:

1. **Identify the Core Subject:** The file name `frame_scheduler_impl_unittest.cc` immediately tells me this is a unit test file specifically for the `FrameSchedulerImpl` class. The directory `blink/renderer/platform/scheduler/main_thread/` further clarifies that this class is part of the main thread scheduler within the Blink rendering engine.

2. **Scan Includes for Dependencies and Context:**  I looked at the `#include` statements. These reveal the classes and functionalities `FrameSchedulerImpl` interacts with:
    *  Core C++ libraries (`<map>`, `<memory>`, etc.)
    *  Base library components (`base/functional/bind.h`, `base/time/time.h`, etc.) – crucial for tasks, callbacks, and time management.
    *  Testing frameworks (`testing/gmock/include/gmock/gmock.h`, `testing/gtest/include/gtest/gtest.h`) – confirming it's a unit test.
    *  Blink public interfaces (`third_party/blink/public/...`) –  indicating interactions with higher-level Blink concepts like features, switches, and scheduling.
    *  Internal Blink scheduler components (`third_party/blink/renderer/platform/scheduler/...`) – revealing dependencies on task queues, page schedulers, and the main thread scheduler.

3. **Analyze the `namespace` Structure:**  The code is within the `blink::scheduler::frame_scheduler_impl_unittest` namespace. This isolates the test code and avoids naming conflicts.

4. **Focus on Key Helper Functions and Classes:**  I noted the presence of helper functions like `CreatePageScheduler`, `CreateFrameScheduler`, and `RecordRunTime`. These simplify test setup and actions. The `FrameSchedulerDelegateForTesting` class is a mock object, vital for isolating `FrameSchedulerImpl` and controlling its dependencies' behavior.

5. **Examine the Test Fixture `FrameSchedulerImplTest`:** This is the central setup for most tests. Key observations:
    *  It inherits from `testing::Test`, a standard GTest fixture.
    *  It sets up a `TaskEnvironment`, crucial for managing time and tasks in a test context.
    *  It creates instances of `MainThreadSchedulerImpl`, `AgentGroupScheduler`, `PageSchedulerImpl`, and `FrameSchedulerImpl`. This reflects the dependency hierarchy of the class being tested.
    *  Helper methods like `PostTestTasksForPrioritisationType` and `PostTestTasksToQueuesWithTrait` are provided to easily schedule tasks for testing different scenarios.
    *  Methods for manipulating the state of the page and frame (visibility, frozen, back/forward cache) are present, indicating testing of lifecycle management.

6. **Infer Functionality from Test Structure and Methods:** Based on the setup and helper methods, I could infer the core functionalities being tested:
    * **Task Scheduling and Execution:**  The presence of various task posting methods and the use of `base::RunLoop` suggest testing how tasks are scheduled, prioritized, and executed.
    * **Lifecycle Management:** Methods like `SetPageVisible`, `SetPageFrozen`, `StorePageInBackForwardCache`, and `ResetForNavigation` point to testing how `FrameSchedulerImpl` reacts to changes in the page and frame lifecycle.
    * **Throttling:** The `IsThrottled` method and tests involving page visibility and hidden states indicate tests for background throttling behavior.
    * **Pausing and Resuming:**  `SetPaused` and `SetPreemptedForCooperativeScheduling` methods show tests for controlling task execution flow.
    * **Back/Forward Cache Interaction:** Tests involving `StorePageInBackForwardCache` and `RestorePageFromBackForwardCache`, along with histograms related to IPC messages, suggest testing behavior related to the back/forward cache.
    * **Task Priority:** Tests like `HighestPriorityInputBlockingTaskQueue` and those related to database access indicate tests for how task priorities are handled.
    * **Integration with other Scheduler Components:** The setup involving `PageSchedulerImpl` and `MainThreadSchedulerImpl` suggests integration testing within the scheduler.

7. **Look for Connections to JavaScript, HTML, and CSS:** While the core of the file is C++ scheduling logic, I considered how the tested functionality *relates* to web technologies:
    * **JavaScript Timers:** The presence of `kJavascriptTimerImmediate`, `kJavascriptTimerDelayedLowNesting`, and `kJavascriptTimerDelayedHighNesting` as task types directly links to JavaScript's `setTimeout` and `setInterval` functions. Testing throttling of these tasks in background tabs is a key aspect.
    * **DOM Manipulation:** `TaskType::kDOMManipulation` indicates that scheduling of tasks related to manipulating the HTML structure is being tested.
    * **Networking:**  `TaskType::kNetworking` and related types show testing of scheduling for network requests, crucial for loading HTML, CSS, and JavaScript resources.
    * **User Interaction:** `TaskType::kUserInteraction` suggests testing how events triggered by user actions (like clicks or key presses) are scheduled.
    * **Animations:** `TaskType::kWorkerAnimation` relates to the scheduling of animation frames, impacting how CSS animations and JavaScript-driven animations are processed.

8. **Identify Potential User/Programming Errors:** Based on the tested scenarios, I could infer common errors:
    * **Incorrect assumptions about task execution order:** Developers might assume tasks are executed in a simple FIFO order, but the scheduler prioritizes tasks based on various factors. The tests highlight this complexity.
    * **Forgetting to handle background throttling:** JavaScript timers behaving differently in background tabs can be a source of bugs if not handled correctly. The throttling tests address this.
    * **Issues with back/forward cache:** Incorrectly assuming resources are always available or not anticipating the frozen state in the back/forward cache can lead to errors. The back/forward cache tests are relevant here.
    * **Misunderstanding task priorities:** Using inappropriate task types for specific operations can lead to performance problems.

9. **Synthesize a Summary:** Finally, I combined all these observations into a concise summary of the file's purpose, its relationship to web technologies, and potential error scenarios. I explicitly mentioned that this is the *first part* and that further analysis will be needed for the subsequent parts.
这是目录为 `blink/renderer/platform/scheduler/main_thread/frame_scheduler_impl_unittest.cc` 的 Chromium Blink 引擎源代码文件，它主要负责对 `FrameSchedulerImpl` 类进行单元测试。 `FrameSchedulerImpl` 是 Blink 渲染引擎中负责管理单个帧的任务调度的核心组件。

**功能归纳:**

这个文件的主要功能是 **测试 `FrameSchedulerImpl` 类的各种功能和行为**。具体来说，它涵盖了以下方面：

* **任务队列管理:** 测试 `FrameSchedulerImpl` 如何创建、管理和调度不同类型的任务队列（例如，可节流队列、加载队列、可暂停队列等）。
* **任务优先级:** 测试不同任务类型的优先级设置以及在不同场景下优先级的变化。
* **页面和帧的生命周期管理:** 测试 `FrameSchedulerImpl` 如何响应页面和帧的可见性、冻结状态、是否在后台等状态的变化，并相应地调整任务调度策略。
* **节流 (Throttling):** 测试在页面不可见或在后台时，如何对某些类型的任务进行节流，例如 JavaScript 定时器。
* **暂停和恢复 (Pausing and Resuming):** 测试如何暂停和恢复任务队列的执行，以及对不同类型队列的影响。
* **Back/Forward Cache (BFCache):** 测试当页面进入或离开 BFCache 时，任务调度器的行为，例如记录意外的 IPC 消息。
* **与 `PageSchedulerImpl` 和 `MainThreadSchedulerImpl` 的交互:**  虽然是 `FrameSchedulerImpl` 的单元测试，但也会涉及到与其父类和兄弟类的交互，以确保整个调度系统的协同工作。
* **性能指标记录:** 测试与性能指标相关的逻辑，例如记录任务的执行时间。
* **功能开关 (Feature Flags):**  测试在不同功能开关启用或禁用状态下 `FrameSchedulerImpl` 的行为。
* **观察者模式 (Observer Pattern):** 测试 `FrameSchedulerImpl` 提供的生命周期状态观察者机制。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`FrameSchedulerImpl` 的功能与 JavaScript, HTML, 和 CSS 的执行有着密切的关系，因为它直接负责调度执行这些代码所需的任务。

* **JavaScript:**
    * **定时器 (setTimeout, setInterval):**  测试中大量涉及到 `kJavascriptTimerDelayedLowNesting` 和 `kJavascriptTimerDelayedHighNesting` 等任务类型，这些直接对应 JavaScript 的定时器功能。例如，测试在页面隐藏后，JavaScript 定时器任务会被节流，降低执行频率，以节省资源。
    * **DOM 操作:** 虽然在提供的代码片段中没有直接针对 DOM 操作的测试，但 `TaskType::kDOMManipulation` 的存在表明 `FrameSchedulerImpl` 也负责调度与 DOM 相关的任务。例如，JavaScript 修改了 HTML 结构后，会产生 DOM 操作任务，由 `FrameSchedulerImpl` 调度执行。
    * **事件处理:** `TaskType::kUserInteraction` 和 `TaskType::kRemoteEvent` 表明用户交互事件和远程事件的处理也是通过 `FrameSchedulerImpl` 调度的。例如，用户点击一个按钮会触发 JavaScript 事件处理函数，这个函数的执行会被调度。
* **HTML:**
    * **资源加载:** `TaskType::kNetworking` 和 `TaskType::kInternalLoading` 等任务类型与 HTML 中引用的资源（如图片、脚本、样式表）的加载有关。`FrameSchedulerImpl` 负责调度这些资源的加载任务。
    * **历史导航:** `TaskType::kHistoryTraversal` 涉及到浏览器历史记录的导航操作，例如前进和后退，这些操作也需要 `FrameSchedulerImpl` 进行调度。
* **CSS:**
    * **样式计算和应用:** 虽然没有直接的 CSS 任务类型在代码中显示，但 CSS 样式计算和应用最终也会转化为需要在主线程执行的任务，这些任务会被 `FrameSchedulerImpl` 调度。
    * **动画:** `TaskType::kWorkerAnimation` 指的是与 Web Worker 中动画相关的任务调度，而主线程的动画任务也由 `FrameSchedulerImpl` 管理。

**逻辑推理的假设输入与输出:**

例如，在测试节流功能时，可以假设以下输入和输出：

* **假设输入:**
    * 页面状态: `SetPageVisible(false)` (页面设置为不可见)
    * 任务类型: `kJavascriptTimerDelayedLowNesting` (JavaScript 延迟定时器任务)
    * 定时器间隔: 10ms
* **预期输出:**
    * 任务执行频率: 在页面隐藏后，定时器任务的实际执行间隔会远大于 10ms，例如 1 秒或 1 分钟，具体取决于节流策略。

**涉及用户或者编程常见的使用错误及举例说明:**

* **错误地假设后台页面的 JavaScript 定时器会以相同的频率执行:**  开发者可能会期望在 `setInterval` 中设置的定时器在后台页面仍然会按照设定的间隔执行，但实际上 `FrameSchedulerImpl` 会进行节流以节省资源。测试用例会验证这种节流行为。
* **不理解任务优先级导致性能问题:** 开发者可能没有意识到不同任务类型有不同的优先级，错误地将一些应该高优先级的任务放在低优先级队列中，导致用户体验下降。测试用例会验证不同任务类型的优先级，确保关键任务能够及时执行。
* **在 BFCache 页面中进行不恰当的操作:**  开发者可能会在页面进入 BFCache 后仍然尝试执行某些操作（例如发送 IPC 消息），而没有意识到页面已经被冻结。测试用例会记录这种意外的 IPC 消息。

**总结 (第 1 部分功能):**

总而言之，这个 `frame_scheduler_impl_unittest.cc` 文件的第一部分主要侧重于 **`FrameSchedulerImpl` 的基础功能测试，包括任务队列管理、页面可见性相关的节流、暂停/恢复、以及与时间相关的操作**。它通过模拟不同的场景和状态，验证 `FrameSchedulerImpl` 是否按照预期的方式调度和执行任务，为 Blink 引擎的稳定运行提供了保障。它也涵盖了一些与 JavaScript 定时器和页面生命周期相关的关键功能测试。

### 提示词
```
这是目录为blink/renderer/platform/scheduler/main_thread/frame_scheduler_impl_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/scheduler/main_thread/frame_scheduler_impl.h"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/memory/raw_ptr.h"
#include "base/metrics/field_trial_param_associator.h"
#include "base/metrics/field_trial_params.h"
#include "base/run_loop.h"
#include "base/task/common/task_annotator.h"
#include "base/task/sequence_manager/test/sequence_manager_for_test.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/test/bind.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_command_line.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "base/time/time.h"
#include "base/unguessable_token.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/switches.h"
#include "third_party/blink/public/platform/scheduler/web_agent_group_scheduler.h"
#include "third_party/blink/public/platform/web_runtime_features.h"
#include "third_party/blink/renderer/platform/scheduler/common/features.h"
#include "third_party/blink/renderer/platform/scheduler/common/task_priority.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/frame_task_queue_controller.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/main_thread_scheduler_impl.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/main_thread_task_queue.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/page_scheduler_impl.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/task_type_names.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_or_worker_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/web_scheduling_priority.h"
#include "third_party/blink/renderer/platform/scheduler/public/web_scheduling_queue_type.h"
#include "third_party/blink/renderer/platform/scheduler/public/web_scheduling_task_queue.h"
#include "third_party/blink/renderer/platform/scheduler/test/web_scheduling_test_helper.h"

using base::sequence_manager::TaskQueue;
using testing::UnorderedElementsAre;

namespace blink {
namespace scheduler {
// To avoid symbol collisions in jumbo builds.
namespace frame_scheduler_impl_unittest {

using FeatureHandle = FrameOrWorkerScheduler::SchedulingAffectingFeatureHandle;
using PrioritisationType = MainThreadTaskQueue::QueueTraits::PrioritisationType;
using testing::Return;

namespace {

constexpr base::TimeDelta kDefaultThrottledWakeUpInterval =
    PageSchedulerImpl::kDefaultThrottledWakeUpInterval;
constexpr base::TimeDelta kIntensiveThrottledWakeUpInterval =
    PageSchedulerImpl::kIntensiveThrottledWakeUpInterval;
constexpr auto kShortDelay = base::Milliseconds(10);

// This is a wrapper around MainThreadSchedulerImpl::CreatePageScheduler, that
// returns the PageScheduler as a PageSchedulerImpl.
std::unique_ptr<PageSchedulerImpl> CreatePageScheduler(
    PageScheduler::Delegate* page_scheduler_delegate,
    MainThreadSchedulerImpl* scheduler,
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

void RecordRunTime(std::vector<base::TimeTicks>* run_times) {
  run_times->push_back(base::TimeTicks::Now());
}

class TestObject {
 public:
  explicit TestObject(int* counter) : counter_(counter) {}

  ~TestObject() { ++(*counter_); }

 private:
  raw_ptr<int> counter_;
};

}  // namespace

// All TaskTypes that can be passed to
// FrameSchedulerImpl::CreateQueueTraitsForTaskType().
constexpr TaskType kAllFrameTaskTypes[] = {
    TaskType::kInternalContentCapture,
    TaskType::kJavascriptTimerImmediate,
    TaskType::kJavascriptTimerDelayedLowNesting,
    TaskType::kJavascriptTimerDelayedHighNesting,
    TaskType::kInternalLoading,
    TaskType::kNetworking,
    TaskType::kNetworkingUnfreezable,
    TaskType::kNetworkingUnfreezableRenderBlockingLoading,
    TaskType::kNetworkingControl,
    TaskType::kLowPriorityScriptExecution,
    TaskType::kDOMManipulation,
    TaskType::kHistoryTraversal,
    TaskType::kEmbed,
    TaskType::kCanvasBlobSerialization,
    TaskType::kRemoteEvent,
    TaskType::kWebSocket,
    TaskType::kMicrotask,
    TaskType::kUnshippedPortMessage,
    TaskType::kFileReading,
    TaskType::kPresentation,
    TaskType::kSensor,
    TaskType::kPerformanceTimeline,
    TaskType::kWebGL,
    TaskType::kIdleTask,
    TaskType::kInternalDefault,
    TaskType::kMiscPlatformAPI,
    TaskType::kFontLoading,
    TaskType::kApplicationLifeCycle,
    TaskType::kBackgroundFetch,
    TaskType::kPermission,
    TaskType::kPostedMessage,
    TaskType::kServiceWorkerClientMessage,
    TaskType::kWorkerAnimation,
    TaskType::kUserInteraction,
    TaskType::kMediaElementEvent,
    TaskType::kInternalWebCrypto,
    TaskType::kInternalMedia,
    TaskType::kInternalMediaRealTime,
    TaskType::kInternalUserInteraction,
    TaskType::kInternalIntersectionObserver,
    TaskType::kInternalFindInPage,
    TaskType::kInternalContinueScriptLoading,
    TaskType::kDatabaseAccess,
    TaskType::kInternalNavigationAssociated,
    TaskType::kInternalTest,
    TaskType::kWebLocks,
    TaskType::kInternalFrameLifecycleControl,
    TaskType::kInternalTranslation,
    TaskType::kInternalInspector,
    TaskType::kInternalNavigationAssociatedUnfreezable,
    TaskType::kInternalHighPriorityLocalFrame,
    TaskType::kInternalInputBlocking,
    TaskType::kWakeLock,
    TaskType::kStorage,
    TaskType::kClipboard,
    TaskType::kMachineLearning,
    TaskType::kWebGPU,
    TaskType::kInternalPostMessageForwarding,
    TaskType::kInternalNavigationCancellation};

static_assert(
    static_cast<int>(TaskType::kMaxValue) == 87,
    "When adding a TaskType, make sure that kAllFrameTaskTypes is updated.");

void AppendToVectorTestTask(Vector<String>* vector, String value) {
  vector->push_back(std::move(value));
}

class FrameSchedulerDelegateForTesting : public FrameScheduler::Delegate {
 public:
  FrameSchedulerDelegateForTesting() = default;

  ~FrameSchedulerDelegateForTesting() override = default;

  ukm::UkmRecorder* GetUkmRecorder() override { return nullptr; }

  ukm::SourceId GetUkmSourceId() override { return ukm::kInvalidSourceId; }

  void UpdateTaskTime(base::TimeDelta unreported_task_time) override {
    update_unreported_task_time_calls_++;
  }

  void OnTaskCompleted(base::TimeTicks,
                       base::TimeTicks) override {}
  const base::UnguessableToken& GetAgentClusterId() const override {
    return base::UnguessableToken::Null();
  }
  MOCK_METHOD(void, UpdateBackForwardCacheDisablingFeatures, (BlockingDetails));

  DocumentResourceCoordinator* GetDocumentResourceCoordinator() override {
    return nullptr;
  }

  int update_unreported_task_time_calls_ = 0;
};

MATCHER(BlockingDetailsHasCCNS, "Blocking details has CCNS.") {
  bool vector_empty =
      arg.non_sticky_features_and_js_locations->details_list.empty();
  bool vector_has_ccns =
      arg.sticky_features_and_js_locations->details_list.Contains(
          FeatureAndJSLocationBlockingBFCache(
              SchedulingPolicy::Feature::kMainResourceHasCacheControlNoStore,
              nullptr)) &&
      arg.sticky_features_and_js_locations->details_list.Contains(
          FeatureAndJSLocationBlockingBFCache(
              SchedulingPolicy::Feature::kMainResourceHasCacheControlNoCache,
              nullptr));
  return vector_empty && vector_has_ccns;
}

MATCHER_P(BlockingDetailsHasWebSocket,
          handle,
          "BlockingDetails has WebSocket.") {
  bool handle_has_web_socket =
      (handle->GetFeatureAndJSLocationBlockingBFCache() ==
       FeatureAndJSLocationBlockingBFCache(
           SchedulingPolicy::Feature::kWebSocket, nullptr));
  bool vector_empty =
      arg.sticky_features_and_js_locations->details_list.empty();
  return handle_has_web_socket && vector_empty;
}

MATCHER(BlockingDetailsIsEmpty, "BlockingDetails is empty.") {
  bool non_sticky_vector_empty =
      arg.non_sticky_features_and_js_locations->details_list.empty();
  bool sticky_vector_empty =
      arg.sticky_features_and_js_locations->details_list.empty();
  return non_sticky_vector_empty && sticky_vector_empty;
}
class FrameSchedulerImplTest : public testing::Test {
 public:
  FrameSchedulerImplTest()
      : task_environment_(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME,
            base::test::TaskEnvironment::ThreadPoolExecutionMode::QUEUED) {}

  // Constructs a FrameSchedulerImplTest with a list of features to enable and a
  // list of features to disable.
  FrameSchedulerImplTest(
      std::vector<base::test::FeatureRef> features_to_enable,
      std::vector<base::test::FeatureRef> features_to_disable)
      : FrameSchedulerImplTest() {
    feature_list_.InitWithFeatures(features_to_enable, features_to_disable);
  }

  // Constructs a FrameSchedulerImplTest with a feature to enable, associated
  // params, and a list of features to disable.
  FrameSchedulerImplTest(
      const base::Feature& feature_to_enable,
      const base::FieldTrialParams& feature_to_enable_params,
      const std::vector<base::test::FeatureRef>& features_to_disable)
      : FrameSchedulerImplTest() {
    feature_list_.InitWithFeaturesAndParameters(
        {{feature_to_enable, feature_to_enable_params}}, features_to_disable);
  }

  ~FrameSchedulerImplTest() override = default;

  void SetUp() override {
    scheduler_ = std::make_unique<MainThreadSchedulerImpl>(
        base::sequence_manager::SequenceManagerForTest::Create(
            nullptr, task_environment_.GetMainThreadTaskRunner(),
            task_environment_.GetMockTickClock(),
            base::sequence_manager::SequenceManager::Settings::Builder()
                .SetPrioritySettings(CreatePrioritySettings())
                .Build()));
    agent_group_scheduler_ = scheduler_->CreateAgentGroupScheduler();
    page_scheduler_ =
        CreatePageScheduler(nullptr, scheduler_.get(), *agent_group_scheduler_);
    frame_scheduler_delegate_ = std::make_unique<
        testing::StrictMock<FrameSchedulerDelegateForTesting>>();
    frame_scheduler_ = CreateFrameScheduler(
        page_scheduler_.get(), frame_scheduler_delegate_.get(),
        /*is_in_embedded_frame_tree=*/false,
        FrameScheduler::FrameType::kSubframe);
  }

  void ResetFrameScheduler(bool is_in_embedded_frame_tree,
                           FrameScheduler::FrameType frame_type) {
    auto new_delegate_ = std::make_unique<
        testing::StrictMock<FrameSchedulerDelegateForTesting>>();
    frame_scheduler_ =
        CreateFrameScheduler(page_scheduler_.get(), new_delegate_.get(),
                             is_in_embedded_frame_tree, frame_type);
    frame_scheduler_delegate_ = std::move(new_delegate_);
  }

  void StorePageInBackForwardCache() {
    page_scheduler_->SetPageVisible(false);
    page_scheduler_->SetPageFrozen(true);
    page_scheduler_->SetPageBackForwardCached(true);
  }

  void RestorePageFromBackForwardCache() {
    page_scheduler_->SetPageVisible(true);
    page_scheduler_->SetPageFrozen(false);
    page_scheduler_->SetPageBackForwardCached(false);
  }

  void TearDown() override {
    throttleable_task_queue_.reset();
    frame_scheduler_.reset();
    page_scheduler_.reset();
    agent_group_scheduler_ = nullptr;
    scheduler_->Shutdown();
    scheduler_.reset();
    frame_scheduler_delegate_.reset();
  }

  // Helper for posting several tasks of specific prioritisation types for
  // testing the relative order of tasks. |task_descriptor| is a string with
  // space delimited task identifiers. The first letter of each task identifier
  // specifies the prioritisation type:
  // - 'R': Regular (normal priority)
  // - 'V': Internal Script Continuation (very high priority)
  // - 'B': Best-effort
  // - 'D': Database
  void PostTestTasksForPrioritisationType(Vector<String>* run_order,
                                          const String& task_descriptor) {
    std::istringstream stream(task_descriptor.Utf8());
    PrioritisationType prioritisation_type;
    while (!stream.eof()) {
      std::string task;
      stream >> task;
      switch (task[0]) {
        case 'R':
          prioritisation_type = PrioritisationType::kRegular;
          break;
        case 'V':
          prioritisation_type = PrioritisationType::kInternalScriptContinuation;
          break;
        case 'B':
          prioritisation_type = PrioritisationType::kBestEffort;
          break;
        case 'D':
          prioritisation_type = PrioritisationType::kExperimentalDatabase;
          break;
        default:
          EXPECT_FALSE(true);
          return;
      }
      auto queue_traits =
          FrameSchedulerImpl::PausableTaskQueueTraits().SetPrioritisationType(
              prioritisation_type);
      GetTaskQueue(queue_traits)
          ->GetTaskRunnerWithDefaultTaskType()
          ->PostTask(FROM_HERE,
                     base::BindOnce(&AppendToVectorTestTask, run_order,
                                    String::FromUTF8(task)));
    }
  }

  // Helper for posting several tasks to specific queues. |task_descriptor| is a
  // string with space delimited task identifiers. The first letter of each task
  // identifier specifies the task queue:
  // - 'L': Loading task queue
  // - 'T': Throttleable task queue
  // - 'P': Pausable task queue
  // - 'U': Unpausable task queue
  // - 'D': Deferrable task queue
  void PostTestTasksToQueuesWithTrait(Vector<String>* run_order,
                                      const String& task_descriptor) {
    std::istringstream stream(task_descriptor.Utf8());
    while (!stream.eof()) {
      std::string task;
      stream >> task;
      switch (task[0]) {
        case 'L':
          LoadingTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
              FROM_HERE, base::BindOnce(&AppendToVectorTestTask, run_order,
                                        String::FromUTF8(task)));
          break;
        case 'T':
          ThrottleableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
              FROM_HERE, base::BindOnce(&AppendToVectorTestTask, run_order,
                                        String::FromUTF8(task)));
          break;
        case 'P':
          PausableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
              FROM_HERE, base::BindOnce(&AppendToVectorTestTask, run_order,
                                        String::FromUTF8(task)));
          break;
        case 'U':
          UnpausableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
              FROM_HERE, base::BindOnce(&AppendToVectorTestTask, run_order,
                                        String::FromUTF8(task)));
          break;
        case 'D':
          DeferrableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
              FROM_HERE, base::BindOnce(&AppendToVectorTestTask, run_order,
                                        String::FromUTF8(task)));
          break;
        default:
          NOTREACHED();
      }
    }
  }

  static void ResetForNavigation(FrameSchedulerImpl* frame_scheduler) {
    frame_scheduler->ResetForNavigation();
  }

  base::TimeDelta GetUnreportedTaskTime() {
    return frame_scheduler_->unreported_task_time_;
  }

  int GetTotalUpdateTaskTimeCalls() {
    return frame_scheduler_delegate_->update_unreported_task_time_calls_;
  }

  void ResetTotalUpdateTaskTimeCalls() {
    frame_scheduler_delegate_->update_unreported_task_time_calls_ = 0;
  }

  // Fast-forwards to the next time aligned on |interval|.
  void FastForwardToAlignedTime(base::TimeDelta interval) {
    const base::TimeTicks now = base::TimeTicks::Now();
    const base::TimeTicks aligned =
        now.SnappedToNextTick(base::TimeTicks(), interval);
    if (aligned != now)
      task_environment_.FastForwardBy(aligned - now);
  }

  // Post and run tasks with delays of 0ms, 50ms, 100ms, 150ms and 200ms. Stores
  // run times in `run_times`.
  void PostAndRunTasks50MsInterval(
      scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      std::vector<base::TimeTicks>* run_times) {
    for (int i = 0; i < 5; i++) {
      task_runner->PostDelayedTask(FROM_HERE,
                                   base::BindOnce(&RecordRunTime, run_times),
                                   base::Milliseconds(50) * i);
    }
    task_environment_.FastForwardBy(base::Seconds(5));
  }

  // Post and run tasks. Expect no alignment.
  void PostTasks_ExpectNoAlignment(
      scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
    FastForwardToAlignedTime(base::Seconds(1));
    const base::TimeTicks start = base::TimeTicks::Now();

    std::vector<base::TimeTicks> run_times;
    PostAndRunTasks50MsInterval(task_runner, &run_times);

    EXPECT_THAT(run_times,
                testing::ElementsAre(start, start + base::Milliseconds(50),
                                     start + base::Milliseconds(100),
                                     start + base::Milliseconds(150),
                                     start + base::Milliseconds(200)));
  }

  // Post and run tasks. Expect 32ms alignment.
  void PostTasks_Expect32msAlignment(
      scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
    FastForwardToAlignedTime(base::Milliseconds(32));
    const base::TimeTicks start = base::TimeTicks::Now();

    std::vector<base::TimeTicks> run_times;
    PostAndRunTasks50MsInterval(task_runner, &run_times);

    EXPECT_THAT(run_times,
                testing::ElementsAre(start, start + base::Milliseconds(64),
                                     start + base::Milliseconds(128),
                                     start + base::Milliseconds(160),
                                     start + base::Milliseconds(224)));
  }

  // Post and run tasks. Expect 1 second alignment.
  void PostTasks_Expect1sAlignment(
      scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
    FastForwardToAlignedTime(base::Seconds(1));
    const base::TimeTicks start = base::TimeTicks::Now();

    std::vector<base::TimeTicks> run_times;
    PostAndRunTasks50MsInterval(task_runner, &run_times);

    EXPECT_THAT(run_times, testing::ElementsAre(start, start + base::Seconds(1),
                                                start + base::Seconds(1),
                                                start + base::Seconds(1),
                                                start + base::Seconds(1)));
  }

 protected:
  scoped_refptr<MainThreadTaskQueue> throttleable_task_queue() {
    return throttleable_task_queue_;
  }

  void LazyInitThrottleableTaskQueue() {
    EXPECT_FALSE(throttleable_task_queue());
    throttleable_task_queue_ = ThrottleableTaskQueue();
    EXPECT_TRUE(throttleable_task_queue());
  }

  scoped_refptr<MainThreadTaskQueue> GetTaskQueue(
      MainThreadTaskQueue::QueueTraits queue_traits) {
    return frame_scheduler_->FrameTaskQueueControllerForTest()->GetTaskQueue(
        queue_traits);
  }

  scoped_refptr<MainThreadTaskQueue> ThrottleableTaskQueue() {
    return GetTaskQueue(FrameSchedulerImpl::ThrottleableTaskQueueTraits());
  }

  scoped_refptr<MainThreadTaskQueue>
  JavaScriptTimerNormalThrottleableTaskQueue() {
    return GetTaskQueue(
        FrameSchedulerImpl::ThrottleableTaskQueueTraits().SetPrioritisationType(
            PrioritisationType::kJavaScriptTimer));
  }

  scoped_refptr<MainThreadTaskQueue>
  JavaScriptTimerIntensivelyThrottleableTaskQueue() {
    return GetTaskQueue(
        FrameSchedulerImpl::ThrottleableTaskQueueTraits()
            .SetPrioritisationType(PrioritisationType::kJavaScriptTimer)
            .SetCanBeIntensivelyThrottled(true));
  }

  scoped_refptr<MainThreadTaskQueue> JavaScriptTimerNonThrottleableTaskQueue() {
    return GetTaskQueue(
        FrameSchedulerImpl::DeferrableTaskQueueTraits().SetPrioritisationType(
            PrioritisationType::kJavaScriptTimer));
  }

  scoped_refptr<MainThreadTaskQueue> LoadingTaskQueue() {
    return GetTaskQueue(FrameSchedulerImpl::LoadingTaskQueueTraits());
  }

  scoped_refptr<MainThreadTaskQueue> LoadingControlTaskQueue() {
    return GetTaskQueue(FrameSchedulerImpl::LoadingControlTaskQueueTraits());
  }

  scoped_refptr<MainThreadTaskQueue> UnfreezableLoadingTaskQueue() {
    return GetTaskQueue(
        FrameSchedulerImpl::UnfreezableLoadingTaskQueueTraits());
  }

  scoped_refptr<MainThreadTaskQueue> DeferrableTaskQueue() {
    return GetTaskQueue(FrameSchedulerImpl::DeferrableTaskQueueTraits());
  }

  scoped_refptr<MainThreadTaskQueue> PausableTaskQueue() {
    return GetTaskQueue(FrameSchedulerImpl::PausableTaskQueueTraits());
  }

  scoped_refptr<MainThreadTaskQueue> UnpausableTaskQueue() {
    return GetTaskQueue(FrameSchedulerImpl::UnpausableTaskQueueTraits());
  }

  scoped_refptr<MainThreadTaskQueue> ForegroundOnlyTaskQueue() {
    return GetTaskQueue(FrameSchedulerImpl::ForegroundOnlyTaskQueueTraits());
  }

  scoped_refptr<MainThreadTaskQueue> InputBlockingTaskQueue() {
    return GetTaskQueue(FrameSchedulerImpl::InputBlockingQueueTraits());
  }

  scoped_refptr<MainThreadTaskQueue> GetTaskQueue(TaskType type) {
    return frame_scheduler_->GetTaskQueue(type);
  }

  bool IsThrottled() {
    EXPECT_TRUE(throttleable_task_queue());
    return throttleable_task_queue()->IsThrottled();
  }

  bool IsTaskTypeThrottled(TaskType task_type) {
    scoped_refptr<MainThreadTaskQueue> task_queue = GetTaskQueue(task_type);
    return task_queue->IsThrottled();
  }

  SchedulingLifecycleState CalculateLifecycleState(
      FrameScheduler::ObserverType type) {
    return frame_scheduler_->CalculateLifecycleState(type);
  }

  void DidCommitProvisionalLoad(
      FrameScheduler::NavigationType navigation_type) {
    frame_scheduler_->DidCommitProvisionalLoad(
        /*is_web_history_inert_commit=*/false, navigation_type,
        {GetUnreportedTaskTime()});
  }

  base::test::ScopedFeatureList feature_list_;
  base::test::TaskEnvironment task_environment_;
  std::unique_ptr<MainThreadSchedulerImpl> scheduler_;
  Persistent<AgentGroupScheduler> agent_group_scheduler_;
  std::unique_ptr<PageSchedulerImpl> page_scheduler_;
  std::unique_ptr<FrameSchedulerImpl> frame_scheduler_;
  std::unique_ptr<testing::StrictMock<FrameSchedulerDelegateForTesting>>
      frame_scheduler_delegate_;
  scoped_refptr<MainThreadTaskQueue> throttleable_task_queue_;
};

class FrameSchedulerImplStopInBackgroundDisabledTest
    : public FrameSchedulerImplTest,
      public ::testing::WithParamInterface<TaskType> {
 public:
  FrameSchedulerImplStopInBackgroundDisabledTest()
      : FrameSchedulerImplTest({}, {blink::features::kStopInBackground}) {}
};

namespace {

class MockLifecycleObserver {
 public:
  MockLifecycleObserver()
      : not_throttled_count_(0u),
        hidden_count_(0u),
        throttled_count_(0u),
        stopped_count_(0u) {}

  inline void CheckObserverState(base::Location from,
                                 size_t not_throttled_count_expectation,
                                 size_t hidden_count_expectation,
                                 size_t throttled_count_expectation,
                                 size_t stopped_count_expectation) {
    EXPECT_EQ(not_throttled_count_expectation, not_throttled_count_)
        << from.ToString();
    EXPECT_EQ(hidden_count_expectation, hidden_count_) << from.ToString();
    EXPECT_EQ(throttled_count_expectation, throttled_count_) << from.ToString();
    EXPECT_EQ(stopped_count_expectation, stopped_count_) << from.ToString();
  }

  void OnLifecycleStateChanged(SchedulingLifecycleState state) {
    switch (state) {
      case SchedulingLifecycleState::kNotThrottled:
        not_throttled_count_++;
        break;
      case SchedulingLifecycleState::kHidden:
        hidden_count_++;
        break;
      case SchedulingLifecycleState::kThrottled:
        throttled_count_++;
        break;
      case SchedulingLifecycleState::kStopped:
        stopped_count_++;
        break;
        // We should not have another state, and compiler checks it.
    }
  }

  FrameOrWorkerScheduler::OnLifecycleStateChangedCallback GetCallback() {
    return base::BindRepeating(&MockLifecycleObserver::OnLifecycleStateChanged,
                               base::Unretained(this));
  }

 private:
  size_t not_throttled_count_;
  size_t hidden_count_;
  size_t throttled_count_;
  size_t stopped_count_;
};

void IncrementCounter(int* counter) {
  ++*counter;
}

// Simulate running a task of a particular length by fast forwarding the task
// environment clock, which is used to determine the wall time of a task.
void RunTaskOfLength(base::test::TaskEnvironment* task_environment,
                     base::TimeDelta length) {
  task_environment->FastForwardBy(length);
}

class FrameSchedulerImplTestWithIntensiveWakeUpThrottlingBase
    : public FrameSchedulerImplTest {
 public:
  using Super = FrameSchedulerImplTest;

  FrameSchedulerImplTestWithIntensiveWakeUpThrottlingBase()
      : FrameSchedulerImplTest({features::kIntensiveWakeUpThrottling},
                               {features::kStopInBackground}) {}

  void SetUp() override {
    Super::SetUp();
    ClearIntensiveWakeUpThrottlingPolicyOverrideCacheForTesting();
  }

  void TearDown() override {
    ClearIntensiveWakeUpThrottlingPolicyOverrideCacheForTesting();
    Super::TearDown();
  }

  const int kNumTasks = 5;
  const base::TimeDelta kGracePeriod =
      GetIntensiveWakeUpThrottlingGracePeriod(false);
};

// Test param for FrameSchedulerImplTestWithIntensiveWakeUpThrottling
struct IntensiveWakeUpThrottlingTestParam {
  // TaskType used to obtain TaskRunners from the FrameScheduler.
  TaskType task_type;
  // Whether it is expected that tasks will be intensively throttled.
  bool is_intensive_throttling_expected;
};

class FrameSchedulerImplTestWithIntensiveWakeUpThrottling
    : public FrameSchedulerImplTestWithIntensiveWakeUpThrottlingBase,
      public ::testing::WithParamInterface<IntensiveWakeUpThrottlingTestParam> {
 public:
  FrameSchedulerImplTestWithIntensiveWakeUpThrottling() = default;

  TaskType GetTaskType() const { return GetParam().task_type; }
  bool IsIntensiveThrottlingExpected() const {
    return GetParam().is_intensive_throttling_expected;
  }

  // Get the TaskRunner from |frame_scheduler_| using the test's task type
  // parameter.
  scoped_refptr<base::SingleThreadTaskRunner> GetTaskRunner() {
    return GetTaskRunner(frame_scheduler_.get());
  }

  // Get the TaskRunner from the provided |frame_scheduler| using the test's
  // task type parameter.
  scoped_refptr<base::SingleThreadTaskRunner> GetTaskRunner(
      FrameSchedulerImpl* frame_scheduler) {
    const TaskType task_type = GetTaskType();
    if (task_type == TaskType::kWebSchedulingPostedTask) {
      test_web_scheduling_task_queues_.push_back(
          frame_scheduler->CreateWebSchedulingTaskQueue(
              WebSchedulingQueueType::kTaskQueue,
              WebSchedulingPriority::kUserVisiblePriority));
      return test_web_scheduling_task_queues_.back()->GetTaskRunner();
    }
    return frame_scheduler->GetTaskRunner(task_type);
  }

  base::TimeDelta GetExpectedWakeUpInterval() const {
    if (IsIntensiveThrottlingExpected())
      return kIntensiveThrottledWakeUpInterval;
    return kDefaultThrottledWakeUpInterval;
  }

 private:
  // Store web scheduling task queues that are created for tests so
  // they do not get destroyed. Destroying them before their tasks finish
  // running will break throttling.
  Vector<std::unique_ptr<WebSchedulingTaskQueue>>
      test_web_scheduling_task_queues_;
};

class FrameSchedulerImplTestWithIntensiveWakeUpThrottlingPolicyOverride
    : public FrameSchedulerImplTestWithIntensiveWakeUpThrottlingBase {
 public:
  FrameSchedulerImplTestWithIntensiveWakeUpThrottlingPolicyOverride() = default;

  // This should only be called once per test, and prior to the
  // PageSchedulerImpl logic actually parsing the policy switch.
  void SetPolicyOverride(bool enabled) {
    DCHECK(!scoped_command_line_.GetProcessCommandLine()->HasSwitch(
        switches::kIntensiveWakeUpThrottlingPolicy));
    scoped_command_line_.GetProcessCommandLine()->AppendSwitchASCII(
        switches::kIntensiveWakeUpThrottlingPolicy,
        enabled ? switches::kIntensiveWakeUpThrottlingPolicy_ForceEnable
                : switches::kIntensiveWakeUpThrottlingPolicy_ForceDisable);
  }

 private:
  base::test::ScopedCommandLine scoped_command_line_;
};

}  // namespace

// Throttleable task queue is initialized lazily, so there're two scenarios:
// - Task queue created first and throttling decision made later;
// - Scheduler receives relevant signals to make a throttling decision but
//   applies one once task queue gets created.
// We test both (ExplicitInit/LazyInit) of them.

TEST_F(FrameSchedulerImplTest, PageVisible) {
  EXPECT_FALSE(throttleable_task_queue());
  LazyInitThrottleableTaskQueue();
  EXPECT_FALSE(IsThrottled());
}

TEST_F(FrameSchedulerImplTest, PageHidden_ExplicitInit) {
  LazyInitThrottleableTaskQueue();
  EXPECT_FALSE(IsThrottled());
  page_scheduler_->SetPageVisible(false);
  EXPECT_TRUE(IsThrottled());
}

TEST_F(FrameSchedulerImplTest, PageHidden_LazyInit) {
  page_scheduler_->SetPageVisible(false);
  LazyInitThrottleableTaskQueue();
  EXPECT_TRUE(IsThrottled());
}

TEST_F(FrameSchedulerImplTest, PageHiddenThenVisible_ExplicitInit) {
  LazyInitThrottleableTaskQueue();
  EXPECT_FALSE(IsThrottled());
  page_scheduler_->SetPageVisible(false);
  EXPECT_TRUE(IsThrottled());
  page_scheduler_->SetPageVisible(true);
  EXPECT_FALSE(IsThrottled());
  page_scheduler_->SetPageVisible(false);
  EXPECT_TRUE(IsThrottled());
}

TEST_F(FrameSchedulerImplTest,
       FrameHiddenThenVisible_CrossOrigin_ExplicitInit) {
  LazyInitThrottleableTaskQueue();
  EXPECT_FALSE(IsThrottled());
  frame_scheduler_->SetFrameVisible(false);
  frame_scheduler_->SetCrossOriginToNearestMainFrame(true);
  frame_scheduler_->SetCrossOriginToNearestMainFrame(false);
  EXPECT_FALSE(IsThrottled());
  frame_scheduler_->SetCrossOriginToNearestMainFrame(true);
  EXPECT_TRUE(IsThrottled());
  frame_scheduler_->SetFrameVisible(true);
  EXPECT_FALSE(IsThrottled());
  frame_scheduler_->SetFrameVisible(false);
  EXPECT_TRUE(IsThrottled());
}

TEST_F(FrameSchedulerImplTest, FrameHidden_CrossOrigin_LazyInit) {
  frame_scheduler_->SetFrameVisible(false);
  frame_scheduler_->SetCrossOriginToNearestMainFrame(true);
  LazyInitThrottleableTaskQueue();
  EXPECT_TRUE(IsThrottled());
}

TEST_F(FrameSchedulerImplTest, FrameHidden_SameOrigin_ExplicitInit) {
  LazyInitThrottleableTaskQueue();
  EXPECT_FALSE(IsThrottled());
  frame_scheduler_->SetFrameVisible(false);
  EXPECT_FALSE(IsThrottled());
}

TEST_F(FrameSchedulerImplTest, FrameHidden_SameOrigin_LazyInit) {
  frame_scheduler_->SetFrameVisible(false);
  LazyInitThrottleableTaskQueue();
  EXPECT_FALSE(IsThrottled());
}

TEST_F(FrameSchedulerImplTest, FrameVisible_CrossOrigin_ExplicitInit) {
  LazyInitThrottleableTaskQueue();
  EXPECT_FALSE(IsThrottled());
  EXPECT_TRUE(throttleable_task_queue());
  frame_scheduler_->SetFrameVisible(true);
  EXPECT_FALSE(IsThrottled());
  frame_scheduler_->SetCrossOriginToNearestMainFrame(true);
  EXPECT_FALSE(IsThrottled());
}

TEST_F(FrameSchedulerImplTest, FrameVisible_CrossOrigin_LazyInit) {
  frame_scheduler_->SetFrameVisible(true);
  frame_scheduler_->SetCrossOriginToNearestMainFrame(true);
  LazyInitThrottleableTaskQueue();
  EXPECT_FALSE(IsThrottled());
}

TEST_F(FrameSchedulerImplTest, PauseAndResume) {
  int counter = 0;
  LoadingTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));
  ThrottleableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));
  DeferrableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));
  PausableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));
  UnpausableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));

  frame_scheduler_->SetPaused(true);

  EXPECT_EQ(0, counter);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, counter);

  frame_scheduler_->SetPaused(false);

  EXPECT_EQ(1, counter);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(5, counter);
}

TEST_F(FrameSchedulerImplTest, PauseAndResumeForCooperativeScheduling) {
  EXPECT_TRUE(LoadingTaskQueue()->IsQueueEnabled());
  EXPECT_TRUE(ThrottleableTaskQueue()->IsQueueEnabled());
  EXPECT_TRUE(DeferrableTaskQueue()->IsQueueEnabled());
  EXPECT_TRUE(PausableTaskQueue()->IsQueueEnabled());
  EXPECT_TRUE(UnpausableTaskQueue()->IsQueueEnabled());

  frame_scheduler_->SetPreemptedForCooperativeScheduling(
      FrameOrWorkerScheduler::Preempted(true));
  EXPECT_FALSE(LoadingTaskQueue()->IsQueueEnabled());
  EXPECT_FALSE(ThrottleableTaskQueue()->IsQueueEnabled());
  EXPECT_FALSE(DeferrableTaskQueue()->IsQueueEnabled());
  EXPECT_FALSE(PausableTaskQueue()->IsQueueEnabled());
  EXPECT_FALSE(UnpausableTaskQueue()->IsQueueEnabled());

  frame_scheduler_->SetPreemptedForCooperativeScheduling(
      FrameOrWorkerScheduler::Preempted(false));
  EXPECT_TRUE(LoadingTaskQueue()->IsQueueEnabled());
  EXPECT_TRUE(ThrottleableTaskQueue()->IsQueueEnabled());
  EXPECT_TRUE(DeferrableTaskQueue()->IsQueueEnabled());
  EXPECT_TRUE(PausableTaskQueue()->IsQueueEnabled());
  EXPECT_TRUE(UnpausableTaskQueue()->IsQueueEnabled());
}

namespace {

// A task that re-posts itself with a delay in order until it has run
// |num_remaining_tasks| times.
void RePostTask(scoped_refptr<base::SingleThreadTaskRunner> task_runner,
                base::TimeDelta delay,
                int* num_remaining_tasks) {
  --(*num_remaining_tasks);
  if (*num_remaining_tasks > 0) {
    task_runner->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&RePostTask, task_runner, delay,
                       base::Unretained(num_remaining_tasks)),
        delay);
  }
}

}  // namespace

// Verify that tasks in a throttled task queue cause:
// - Before intensive wake up throttling kicks in: 1 wake up per second
// - After intensive wake up throttling kick in:
//    - Low nesting level: 1 wake up per second
//    - High nesting level: 1 wake up per minute
// Disable the kStopInBackground feature because it hides the effect of
// intensive wake up throttling.
// Flake test: crbug.com/1328967
TEST_P(FrameSchedulerImplStopInBackgroundDisabledTest,
       DISABLED_ThrottledTaskExecution) {
  // This TaskRunner is throttled.
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      frame_scheduler_->GetTaskRunner(GetParam());

  // Hide the page. This enables wake up throttling.
  EXPECT_TRUE(page_scheduler_->IsPageVisible());
  page_scheduler_->SetPageVisible(false);

  // Schedule tasks with a short delay, during the intensive wake up throttling
  // grace period.
  int num_remaining_tasks =
      base::Seconds(kIntensiveWakeUpThrottling_GracePeriodSeconds_Default)
          .IntDiv(kDefaultThrottledWakeUpInterval);
  task_runner->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&RePostTask, task_runner, kShortDelay,
                     base::Unretained(&num_remaining_tasks)),
      kShortDelay);

  // A task should run every second.
  while (num_remaining_tasks > 0) {
    int previous_num_remaining_tasks = num_remaining_tasks;
    task_environment_.FastForwardBy(kDefaultThrottledWakeUpInterval);
    EXPECT_EQ(previous_num_remaining_tasks - 1, num_remaining_tasks);
  }

  // Schedule tasks with a short delay, after the intensive wake up throttling
  // grace period.
  num_remaining_tasks = 5;
  task_runner->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&RePostTask, task_runner, kShortDelay,
                     base::Unretained(&num_remaining_tasks)),
      kShortDelay);

  // Task run every minute if the nesting level is high, or every second
  // otherwise.
  const base::TimeDelta expected_period_after_grace_period =
      (GetParam() == TaskType::kJavascriptTimerDelayedLowNesting)
          ? kDefaultThrottledWakeUpInterval
          : kIntensiveThrottledWakeUpInterval;

  while (num_remaining_tasks > 0) {
    int previous_num_remaining_tasks = num_remaining_tasks;
    task_environment_.FastForwardBy(expected_period_after_grace_period);
    EXPECT_EQ(previous_num_remaining_tasks - 1, num_remaining_tasks);
  }
}

INSTANTIATE_TEST_SUITE_P(
    AllTimerTaskTypes,
    FrameSchedulerImplStopInBackgroundDisabledTest,
    testing::Values(TaskType::kJavascriptTimerDelayedLowNesting,
                    TaskType::kJavascriptTimerDelayedHighNesting),
    [](const testing::TestParamInfo<TaskType>& info) {
      return TaskTypeNames::TaskTypeToString(info.param);
    });

TEST_F(FrameSchedulerImplTest, FreezeForegroundOnlyTasks) {
  int counter = 0;
  ForegroundOnlyTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));

  frame_scheduler_->SetFrameVisible(false);

  EXPECT_EQ(0, counter);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, counter);

  frame_scheduler_->SetFrameVisible(true);

  EXPECT_EQ(0, counter);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, counter);
}

TEST_F(FrameSchedulerImplTest, PageFreezeAndUnfreeze) {
  int counter = 0;
  LoadingTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));
  ThrottleableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));
  DeferrableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));
  PausableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));
  UnpausableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));

  page_scheduler_->SetPageVisible(false);
  page_scheduler_->SetPageFrozen(true);

  EXPECT_EQ(0, counter);
  base::RunLoop().RunUntilIdle();
  // unpausable tasks continue to run.
  EXPECT_EQ(1, counter);

  page_scheduler_->SetPageFrozen(false);

  EXPECT_EQ(1, counter);
  task_environment_.FastForwardUntilNoTasksRemain();
  EXPECT_EQ(5, counter);
}

// Similar to PageFreezeAndUnfreeze, but unfreezes task queues by making the
// page visible instead of by invoking SetPageFrozen(false).
TEST_F(FrameSchedulerImplTest, PageFreezeAndPageVisible) {
  int counter = 0;
  LoadingTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));
  ThrottleableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));
  DeferrableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));
  PausableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));
  UnpausableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));

  page_scheduler_->SetPageVisible(false);
  page_scheduler_->SetPageFrozen(true);

  EXPECT_EQ(0, counter);
  base::RunLoop().RunUntilIdle();
  // unpausable tasks continue to run.
  EXPECT_EQ(1, counter);

  // Making the page visible should cause frozen queues to resume.
  page_scheduler_->SetPageVisible(true);

  EXPECT_EQ(1, counter);
  task_environment_.FastForwardUntilNoTasksRemain();
  EXPECT_EQ(5, counter);
}

TEST_F(FrameSchedulerImplTest, PagePostsCpuTasks) {
  EXPECT_TRUE(GetUnreportedTaskTime().is_zero());
  EXPECT_EQ(0, GetTotalUpdateTaskTimeCalls());
  UnpausableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&RunTaskOfLength, &task_environment_,
                                base::Milliseconds(10)));
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(GetUnreportedTaskTime().is_zero());
  EXPECT_EQ(0, GetTotalUpdateTaskTimeCalls());
  UnpausableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&RunTaskOfLength, &task_environment_,
                                base::Milliseconds(100)));
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(GetUnreportedTaskTime().is_zero());
  EXPECT_EQ(1, GetTotalUpdateTaskTimeCalls());
}

TEST_F(FrameSchedulerImplTest, FramePostsCpuTasksThroughReloadRenavigate) {
  const struct {
    bool embedded_frame_tree;
    FrameScheduler::FrameType frame_type;
    FrameScheduler::NavigationType navigation_type;
    bool expect_unreported_task_time_zero;
    int expected_total_calls;
  } kTestCases[] = {{false, FrameScheduler::FrameType::kMainFrame,
                     FrameScheduler::NavigationType::kOther, false, 0},
                    {false, FrameScheduler::FrameType::kMainFrame,
                     FrameScheduler::NavigationType::kReload, false, 0},
                    {false, FrameScheduler::FrameType::kMainFrame,
                     FrameScheduler::NavigationType::kSameDocument, true, 1},
                    {false, FrameScheduler::FrameType::kSubframe,
                     FrameScheduler::NavigationType::kOther, true, 1},
                    {false, FrameScheduler::FrameType::kSubframe,
                     FrameScheduler::NavigationType::kSameDocument, true, 1},
                    {true, FrameScheduler::FrameType::kMainFrame,
                     FrameScheduler::NavigationType::kOther, true, 1},
                    {true, FrameScheduler::FrameType::kMainFrame,
                     FrameScheduler::NavigationType::kSameDocument, true, 1},
                    {true, FrameScheduler::FrameType::kSubframe,
                     FrameScheduler::NavigationType::kOther, true, 1},
                    {true, FrameScheduler::FrameType::kSubframe,
                     FrameScheduler::NavigationType::kSameDocument, true, 1}};
  for (const auto& test_case : kTestCases) {
    SCOPED_TRACE(String::Format(
        "FrameType: %d, NavigationType: %d : TaskTime.is_zero %d, CallCount %d",
        static_cast<int>(test_case.frame_type),
        static_cast<int>(test_case.navigation_type),
        test_case.expect_unreported_task_time_zero,
        test_case.expected_total_calls));
    ResetFrameScheduler(test_case.embedded_frame_tree, test_case.frame_type);
    EXPECT_TRUE(GetUnreportedTaskTime().is_zero());
    EXPECT_EQ(0, GetTotalUpdateTaskTimeCalls());

    // Check the rest of the values after different types of commit.
    UnpausableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
        FROM_HERE, base::BindOnce(&RunTaskOfLength, &task_environment_,
                                  base::Milliseconds(60)));
    base::RunLoop().RunUntilIdle();
    EXPECT_FALSE(GetUnreportedTaskTime().is_zero());
    EXPECT_EQ(0, GetTotalUpdateTaskTimeCalls());

    DidCommitProvisionalLoad(test_case.navigation_type);

    UnpausableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
        FROM_HERE, base::BindOnce(&RunTaskOfLength, &task_environment_,
                                  base::Milliseconds(60)));
    base::RunLoop().RunUntilIdle();
    EXPECT_EQ(test_case.expect_unreported_task_time_zero,
              GetUnreportedTaskTime().is_zero());
    EXPECT_EQ(test_case.expected_total_calls, GetTotalUpdateTaskTimeCalls());
  }
}

class FrameSchedulerImplTestWithUnfreezableLoading
    : public FrameSchedulerImplTest {
 public:
  FrameSchedulerImplTestWithUnfreezableLoading()
      : FrameSchedulerImplTest({blink::features::kLoadingTasksUnfreezable},
                               {}) {
    WebRuntimeFeatures::EnableBackForwardCache(true);
  }
};

TEST_F(FrameSchedulerImplTestWithUnfreezableLoading,
       LoadingTasksKeepRunningWhenFrozen) {
  int counter = 0;
  UnfreezableLoadingTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));
  LoadingTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));

  page_scheduler_->SetPageVisible(false);
  page_scheduler_->SetPageFrozen(true);

  EXPECT_EQ(0, counter);
  base::RunLoop().RunUntilIdle();
  // Unfreezable tasks continue to run.
  EXPECT_EQ(1, counter);

  page_scheduler_->SetPageFrozen(false);

  EXPECT_EQ(1, counter);
  // Same as RunUntilIdle but also advances the clock if necessary.
  task_environment_.FastForwardUntilNoTasksRemain();
  // Freezable tasks resume.
  EXPECT_EQ(2, counter);
}

// Tests if throttling observer callbacks work.
TEST_F(FrameSchedulerImplTest, LifecycleObserver) {
  std::unique_ptr<MockLifecycleObserver> observer =
      std::make_unique<MockLifecycleObserver>();

  size_t not_throttled_count = 0u;
  size_t hidden_count = 0u;
  size_t throttled_count = 0u;
  size_t stopped_count = 0u;

  observer->CheckObserverState(FROM_HERE, not_throttled_count, hidden_count,
                               throttled_count, stopped_count);

  auto observer_handle = frame_scheduler_->AddLifecycleObserver(
      FrameScheduler::ObserverType::kLoader, observer->GetCallback());

  // Initial state should be synchronously notified here.
  // We assume kNotThrottled is notified as an initial state, but it could
  // depend on implementation details and can be changed.
  observer->CheckObserverState(FROM_HERE, ++not_throttled_count, hidden_count,
                               throttled_count, stopped_count);

  // Once the page gets to be invisible, it should notify the observer of
  // kHidden synchronously.
  page_scheduler_->SetPageVisible(false);
  observer->CheckObserverState(FROM_HERE, not_throttled_count, ++hidden_count,
                               throttled_count, stopped_count);

  // We do not issue new notifications without actually changing visibility
  // state.
  page_scheduler_->SetPageVisible(false);
  observer->CheckObserverState(FROM_HERE, not_throttled_count, hidden_count,
                               throttled_count, stopped_count);

  task_environment_.FastForwardBy(base::Seconds(30));

  // The frame gets throttled after some time in background.
  observer->CheckObserverState(FROM_HERE, not_throttled_count, hidden_count,
                               ++throttled_count, stopped_count);

  // We shouldn't issue new notifications for kThrottled state as well.
  page_scheduler_->SetPageVisible(false);
  observer->CheckObserverState(FROM_HERE, not_throttled_count, hidden_count,
                               throttled_count, stopped_count);

  // Setting background page to STOPPED, notifies observers of kStopped.
  page_scheduler_->SetPageFrozen(true);
  observer->CheckObserverState(FROM_HERE, not_throttled_count, hidden_count,
                               throttled_count, ++stopped_count);

  // When page is not in the STOPPED state, then page visibility is used,
  // notifying observer of kThrottled.
  page_scheduler_->SetPageFrozen(false);
  observer->CheckObserverState(FROM_HERE, not_throttled_count, hidden_count,
                               ++throttled_count, stopped_count);

  // Going back to visible state should notify the observer of kNotThrottled
  // synchronously.
  page_scheduler_->SetPageVisible(true);
  observer->CheckObserverState(FROM_HERE, ++not_throttled_count, hidden_count,
                               throttled_count, stopped_count);

  // Remove from the observer list, and see if any other callback should not be
  // invoked when the condition is changed.
  observer_handle.reset();
  page_scheduler_->SetPageVisible(false);

  // Wait 100 secs virtually and run pending tasks just in case.
  task_environment_.FastForwardBy(base::Seconds(100));
  base::RunLoop().RunUntilIdle();

  observer->CheckObserverState(FROM_HERE, not_throttled_count, hidden_count,
                               throttled_count, stopped_count);
}

TEST_F(FrameSchedulerImplTest, DefaultSchedulingLifecycleState) {
  EXPECT_EQ(CalculateLifecycleState(FrameScheduler::ObserverType::kLoader),
            SchedulingLifecycleState::kNotThrottled);
  EXPECT_EQ(
      CalculateLifecycleState(FrameScheduler::ObserverType::kWorkerScheduler),
      SchedulingLifecycleState::kNotThrottled);
}

TEST_F(FrameSchedulerImplTest, SubesourceLoadingPaused) {
  // A loader observer and related counts.
  std::unique_ptr<MockLifecycleObserver> loader_observer =
      std::make_unique<MockLifecycleObserver>();

  size_t loader_throttled_count = 0u;
  size_t loader_not_throttled_count = 0u;
  size_t loader_hidden_count = 0u;
  size_t loader_stopped_count = 0u;

  // A worker observer and related counts.
  std::unique_ptr<MockLifecycleObserver> worker_observer =
      std::make_unique<MockLifecycleObserver>();

  size_t worker_throttled_count = 0u;
  size_t worker_not_throttled_count = 0u;
  size_t worker_hidden_count = 0u;
  size_t worker_stopped_count = 0u;

  // Both observers should start with no responses.
  loader_observer->CheckObserverState(
      FROM_HERE, loader_not_throttled_count, loader_hidden_count,
      loader_throttled_count, loader_stopped_count);

  worker_observer->CheckObserverState(
      FROM_HERE, worker_not_throttled_count, worker_hidden_count,
      worker_throttled_count, worker_stopped_count);

  // Adding the observers should recieve a non-throttled response
  auto loader_observer_handle = frame_scheduler_->AddLifecycleObserver(
      FrameScheduler::ObserverType::kLoader, loader_observer->GetCallback());

  auto worker_observer_handle = frame_scheduler_->AddLifecycleObserver(
      FrameScheduler::ObserverType::kWorkerScheduler,
      worker_observer->GetCallback());

  loader_observer->CheckObserverState(
      FROM_HERE, ++loader_not_throttled_count, loader_hidden_count,
      loader_throttled_count, loader_stopped_count);

  worker_observer->CheckObserverState(
      FROM_HERE, ++worker_not_throttled_count, worker_hidden_count,
      worker_throttled_count, worker_stopped_count);

  {
    auto pause_handle_a = frame_scheduler_->GetPauseSubresourceLoadingHandle();

    loader_observer->CheckObserverState(
        FROM_HERE, loader_not_throttled_count, loader_hidden_count,
        loader_throttled_count, ++loader_stopped_count);

    worker_observer->CheckObserverState(
        FROM_HERE, ++worker_not_throttled_count, worker_hidden_count,
        worker_throttled_count, worker_stopped_count);

    std::unique_ptr<MockLifecycleObserver> loader_observer_added_after_stopped =
        std::make_unique<MockLifecycleObserver>();

    auto loader_observer_added_after_stopped_handle =
        frame_scheduler_->AddLifecycleObserver(
            FrameScheduler::ObserverType::kLoader,
            loader_observer_added_after_stopped->GetCallback());
    // This observer should see stopped when added.
    loader_observer_added_after_stopped->CheckObserverState(FROM_HERE, 0, 0, 0,
                                                            1u);

    // Adding another handle should not create a new state.
    auto pause_handle_b = frame_scheduler_->GetPauseSubresourceLoadingHandle();

    loader_observer->CheckObserverState(
        FROM_HERE, loader_not_throttled_count, loader_hidden_count,
        loader_throttled_count, loader_stopped_count);

    worker_observer->CheckObserverState(
        FROM_HERE, worker_not_throttled_count, worker_hidden_count,
        worker_throttled_count, worker_stopped_count);
  }

  // Removing the handles should return the state to non throttled.
  loader_observer->CheckObserverState(
      FROM_HERE, ++loader_not_throttled_count, loader_hidden_count,
      loader_throttled_count, loader_stopped_count);

  worker_observer->CheckObserverState(
      FROM_HERE, ++worker_not_throttled_count, worker_hidden_count,
      worker_throttled_count, worker_stopped_count);
}

TEST_F(FrameSchedulerImplTest, LogIpcsPostedToFramesInBackForwardCache) {
  base::HistogramTester histogram_tester;

  // Create the task queue implicitly.
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      frame_scheduler_->GetTaskRunner(TaskType::kInternalTest);

  StorePageInBackForwardCache();

  // Run the tasks so that they are recorded in the histogram
  task_environment_.FastForwardBy(base::Hours(1));

  // Post IPC tasks, accounting for delay for when tracking starts.
  {
    base::TaskAnnotator::ScopedSetIpcHash scoped_set_ipc_hash(1);
    task_runner->PostTask(FROM_HERE, base::DoNothing());
  }
  {
    base::TaskAnnotator::ScopedSetIpcHash scoped_set_ipc_hash_2(2);
    task_runner->PostTask(FROM_HERE, base::DoNothing());
  }
  // Logging is delayed by one second, so guarantee that our IPCS are logged.
  task_environment_.FastForwardBy(base::Seconds(2));
  task_environment_.RunUntilIdle();

  // Once the page is restored from the cache, IPCs should no longer be
  // recorded.
  RestorePageFromBackForwardCache();

  // Start posting tasks immediately - will not be recorded
  {
    base::TaskAnnotator::ScopedSetIpcHash scoped_set_ipc_hash_3(3);
    task_runner->PostTask(FROM_HERE, base::DoNothing());
  }
  {
    base::TaskAnnotator::ScopedSetIpcHash scoped_set_ipc_hash_4(4);
    task_runner->PostTask(FROM_HERE, base::DoNothing());
  }

  EXPECT_THAT(
      histogram_tester.GetAllSamples(
          "BackForwardCache.Experimental."
          "UnexpectedIPCMessagePostedToCachedFrame.MethodHash"),
      testing::UnorderedElementsAre(base::Bucket(1, 1), base::Bucket(2, 1)));

  // TimeUntilIPCReceived should have values in the 300000 bucket corresponding
  // with the hour delay in task_environment_.FastForwardBy.
  EXPECT_THAT(
      histogram_tester.GetAllSamples(
          "BackForwardCache.Experimental."
          "UnexpectedIPCMessagePostedToCachedFrame.TimeUntilIPCReceived"),
      testing::UnorderedElementsAre(base::Bucket(300000, 2)));
}

TEST_F(FrameSchedulerImplTest,
       LogIpcsFromMultipleThreadsPostedToFramesInBackForwardCache) {
  base::HistogramTester histogram_tester;

  // Create the task queue explicitly to ensure it exists when the page enters
  // the back-forward cache, and that the IPC handler is registerd as well.
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      frame_scheduler_->GetTaskRunner(TaskType::kInternalTest);

  StorePageInBackForwardCache();

  // Run the tasks so that they are recorded in the histogram
  task_environment_.FastForwardBy(base::Hours(1));

  base::ThreadPool::PostTask(
      FROM_HERE,
      base::BindOnce(
          [](scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
            base::TaskAnnotator::ScopedSetIpcHash scoped_set_ipc_hash(1);
            task_runner->PostTask(FROM_HERE, base::DoNothing());
          },
          task_runner));
  task_environment_.RunUntilIdle();

  base::RepeatingClosure restore_from_cache_callback = base::BindRepeating(
      &FrameSchedulerImplTest::RestorePageFromBackForwardCache,
      base::Unretained(this));

  base::ThreadPool::PostTask(
      FROM_HERE,
      base::BindOnce(
          [](scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
            {
              base::TaskAnnotator::ScopedSetIpcHash scoped_set_ipc_hash(2);
              task_runner->PostTask(FROM_HERE, base::DoNothing());
            }
          },
          task_runner));
  // Logging is delayed by one second, so guarantee that our IPCS are logged.
  task_environment_.FastForwardBy(base::Seconds(2));
  base::ThreadPool::PostTask(
      FROM_HERE,
      base::BindOnce(
          [](scoped_refptr<base::SingleThreadTaskRunner> task_runner,
             base::RepeatingClosure restore_from_cache_callback) {
            {
              // Once the page is restored from the cache, ensure that the IPC
              // restoring the page from the cache is not recorded as well.
              base::TaskAnnotator::ScopedSetIpcHash scoped_set_ipc_hash(3);
              task_runner->PostTask(FROM_HERE, restore_from_cache_callback);
            }
            {
              base::TaskAnnotator::ScopedSetIpcHash scoped_set_ipc_hash(4);
              task_runner->PostTask(FROM_HERE, base::DoNothing());
            }
          },
          task_runner, restore_from_cache_callback));
  task_environment_.RunUntilIdle();

  // Start posting tasks immediately - will not be recorded
  base::ThreadPool::PostTask(
      FROM_HERE,
      base::BindOnce(
          [](scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
            base::TaskAnnotator::ScopedSetIpcHash scoped_set_ipc_hash(5);
            task_runner->PostTask(FROM_HERE, base::DoNothing());
          },
          task_runner));
  task_environment_.RunUntilIdle();

  base::ThreadPool::PostTask(
      FROM_HERE,
      base::BindOnce(
          [](scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
            base::TaskAnnotator::ScopedSetIpcHash scoped_set_ipc_hash(6);
            task_runner->PostTask(FROM_HERE, base::DoNothing());
          },
          task_runner));
  task_environment_.RunUntilIdle();

  EXPECT_THAT(
      histogram_tester.GetAllSamples(
          "BackForwardCache.Experimental."
          "UnexpectedIPCMessagePostedToCachedFrame.MethodHash"),
      testing::UnorderedElementsAre(base::Bucket(1, 1), base::Bucket(2, 1)));
}

// TODO(farahcharab) Move priority testing to MainThreadTaskQueueTest after
// landing the change that moves priority computation to MainThreadTaskQueue.

TEST_F(FrameSchedulerImplTest, HighestPriorityInputBlockingTaskQueue) {
  page_scheduler_->SetPageVisible(false);
  EXPECT_EQ(InputBlockingTaskQueue()->GetQueuePriority(),
            TaskPriority::kHighestPriority);
  page_scheduler_->SetPageVisible(true);
  EXPECT_EQ(InputBlockingTaskQueue()->GetQueuePriority(),
            TaskPriority::kHighestPriority);
}

TEST_F(FrameSchedulerImplTest, RenderBlockingRenderBlockingLoading) {
  auto render_blocking_task_queue =
      GetTaskQueue(TaskType::kNetworkingUnfreezableRenderBlockingLoading);
  page_scheduler_->SetPageVisible(false);
  EXPECT_EQ(render_blocking_task_queue->GetQueuePriority(),
            TaskPriority::kNormalPriority);
  page_scheduler_->SetPageVisible(true);
  EXPECT_EQ(render_blocking_task_queue->GetQueuePriority(),
            TaskPriority::kExtremelyHighPriority);
}

TEST_F(FrameSchedulerImplTest, TaskTypeToTaskQueueMapping) {
  // Make sure the queue lookup and task type to queue traits map works as
  // expected. This test will fail if these task types are moved to different
  // default queues.
  EXPECT_EQ(GetTaskQueue(TaskType::kJavascriptTimerDelayedLowNesting),
            JavaScriptTimerNormalThrottleableTaskQueue());
  EXPECT_EQ(GetTaskQueue(TaskType::kJavascriptTimerDelayedHighNesting),
            JavaScriptTimerIntensivelyThrottleableTaskQueue());
  EXPECT_EQ(GetTaskQueue(TaskType::kJavascriptTimerImmediate),
            JavaScriptTimerNonThrottleableTaskQueue());

  EXPECT_EQ(GetTaskQueue(TaskType::kWebSocket), DeferrableTaskQueue());
  EXPECT_EQ(GetTaskQueue(TaskType::kDatabaseAccess), PausableTaskQueue());
  EXPECT_EQ(GetTaskQueue(TaskType::kPostedMessage), PausableTaskQueue());
  EXPECT_EQ(GetTaskQueue(TaskType::kWebLocks), UnpausableTaskQueue());
  EXPECT_EQ(GetTaskQueue(TaskType::kNetworking), LoadingTaskQueue());
  EXPECT_EQ(GetTaskQueue(TaskType::kNetworkingControl),
            LoadingControlTaskQueue());
  EXPECT_EQ(GetTaskQueue(TaskType::kInternalTranslation),
            ForegroundOnlyTaskQueue());
}

// Verify that kJavascriptTimer* are the only non-internal TaskType that can be
// throttled. This ensures that the Javascript timer throttling experiment only
// affects wake ups from Javascript timers https://crbug.com/1075553
TEST_F(FrameSchedulerImplTest, ThrottledTaskTypes) {
  page_scheduler_->SetPageVisible(false);

  for (TaskType task_type : kAllFrameTaskTypes) {
    SCOPED_TRACE(testing::Message()
                 << "TaskType is "
                 << TaskTypeNames::TaskTypeToString(task_type));
    switch (task_type) {
      case TaskType::kInternalContentCapture:
      case TaskType::kJavascriptTimerDelayedLowNesting:
      case TaskType::kJavascriptTimerDelayedHighNesting:
      case TaskType::kInternalTranslation:
        EXPECT_TRUE(IsTaskTypeThrottled(task_type));
        break;
      default:
        EXPECT_FALSE(IsTaskTypeThrottled(task_type));
        break;
    };
  }
}

class FrameSchedulerImplDatabaseAccessWithoutHighPriority
    : public FrameSchedulerImplTest {
 public:
  FrameSchedulerImplDatabaseAccessWithoutHighPriority()
      : FrameSchedulerImplTest({}, {kHighPriorityDatabaseTaskType}) {}
};

TEST_F(FrameSchedulerImplDatabaseAccessWithoutHighPriority, QueueTraits) {
  auto da_queue = GetTaskQueue(TaskType::kDatabaseAccess);
  EXPECT_EQ(da_queue->GetQueueTraits().prioritisation_type,
            MainThreadTaskQueue::QueueTraits::PrioritisationType::kRegular);
  EXPECT_EQ(da_queue->GetQueuePriority(), TaskPriority::kNormalPriority);
}

class FrameSchedulerImplDatabaseAccessWithHighPriority
    : public FrameSchedulerImplTest {
 public:
  FrameSchedulerImplDatabaseAccessWithHighPriority()
      : FrameSchedulerImplTest({kHighPriorityDatabaseTaskType}, {}) {}
};

TEST_F(FrameSchedulerImplDatabaseAccessWithHighPriority, QueueTraits) {
  auto da_queue = GetTaskQueue(TaskType::kDatabaseAccess);
  EXPECT_EQ(da_queue->GetQueueTraits().prioritisation_type,
            MainThreadTaskQueue::QueueTraits::PrioritisationType::
                kExperimentalDatabase);
  EXPECT_EQ(da_queue->GetQueuePriority(), TaskPriority::kHighPriority);
}

TEST_F(FrameSchedulerImplDatabaseAccessWithHighPriority, RunOrder) {
  Vector<String> run_order;
  PostTestTasksForPrioritisationType(&run_order, "D1 R1 D2 V1 B1");

  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("V1", "D1", "D2", "R1", "B1"));
}

TEST_F(FrameSchedulerImplDatabaseAccessWithHighPriority,
       NormalPriorityInBackground) {
  page_scheduler_->SetPageVisible(false);

  Vector<String> run_order;
  PostTestTasksForPrioritisationType(&run_order, "D1 R1 D2 V1 B1");

  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("V1", "D1", "R1", "D2", "B1"));
}

TEST_F(FrameSchedulerImplTest, ContentCaptureHasIdleTaskQueue) {
  auto task_queue = GetTaskQueue(TaskType::kInternalContentCapture);

  EXPECT_EQ(TaskPriority::kBestEffortPriority, task_queue->GetQueuePriority());
}

TEST_F(FrameSchedulerImplTest, ComputePriorityForDetachedFrame) {
  auto task_queue = GetTaskQueue(TaskType::kJavascriptTimerDelayedLowNesting);
  // Just check that it does not crash.
  page_scheduler_.reset();
  frame_scheduler_->ComputePriority(task_queue.get());
}

class FrameSchedulerImplLowPriorityAsyncScriptExecutionTest
    : public FrameSchedulerImplTest,
      public testing::WithParamInterface<std::string> {
 public:
  FrameSchedulerImplLowPriorityAsyncScriptExecutionTest()
      : FrameSchedulerImplTest(
            features::kLowPriorityAsyncScriptExecution,
            {{features::kLowPriorityAsyncScriptExecutionLowerTaskPriorityParam
                  .name,
              specified_priority()}},
            {}) {}

  std::string specified_priority() { return GetParam(); }
  TaskPriority GetExpectedPriority() {
    if (specified_priority() == "high") {
      return TaskPriority::kHighPriority;
    } else if (specified_priority() == "low") {
      return TaskPriority::kLowPriority;
    } else if (specified_priority() == "best_effort") {
      return TaskPriority::kBestEffortPriority;
    }
    NOTREACHED();
  }
};

INSTANTIATE_TEST_SUITE_P(All,
                         FrameSchedulerImplLowPriorityAsyncScriptExecutionTest,
                         testing::Valu
```