Response:
The user wants to understand the functionality of the `resource_load_scheduler_test.cc` file in the Chromium Blink engine. I need to analyze the test cases to determine what aspects of the `ResourceLoadScheduler` they are verifying. Specifically, I should look for:

1. **Core Functionality:** What are the primary actions the `ResourceLoadScheduler` performs? (e.g., queuing, scheduling, throttling).
2. **Interaction with other systems:** Does it interact with JavaScript, HTML, or CSS loading? How?
3. **Logic and Reasoning:** Are there tests that demonstrate specific logical pathways or decision-making within the scheduler? I should try to infer input/output for these scenarios.
4. **Error Handling/User Mistakes:** Are there any tests that implicitly or explicitly cover common mistakes in using the scheduler?

**Detailed Plan:**

1. **Analyze Each Test Case:** Go through each `TEST_F` function and understand its purpose. Identify the specific behavior of the `ResourceLoadScheduler` being tested.
2. **Identify Core Functionalities:** Based on the test cases, list the main responsibilities of the `ResourceLoadScheduler`. Keywords like "Throttle," "Stop," "Priority," "Release" will be important.
3. **Relate to Web Technologies (JavaScript, HTML, CSS):** Consider how resource loading is fundamental to these technologies. Think about when the scheduler would be involved in fetching assets required by these technologies.
4. **Infer Logic and Reasoning:** For tests involving priority, throttling, and state changes, try to deduce the underlying logic. Formulate hypothetical inputs (e.g., request priority, scheduler state) and expected outputs (e.g., request execution order, whether a request is run).
5. **Identify Potential Usage Errors:** Look for test cases that implicitly show incorrect usage patterns (e.g., releasing the same ID twice, releasing an invalid ID). Frame these as common mistakes a developer might make when interacting with the scheduler.

**Self-Correction/Refinement:**

* **Initial Thought:** Focus heavily on the direct API calls being tested.
* **Refinement:** Broaden the scope to understand *why* these API calls are being tested. What broader behavior are they validating?  This will help connect the scheduler to higher-level concepts like web page loading.
* **Initial Thought:**  Treat each test case as an isolated unit.
* **Refinement:** Look for patterns and common themes across multiple test cases to get a more holistic understanding of the scheduler's capabilities.
* **Initial Thought:**  Only focus on explicitly stated errors.
* **Refinement:**  Consider *implicit* errors demonstrated by the tests – situations where the test verifies that something *doesn't* happen under certain conditions, which can indicate a potential misuse scenario.
这个文件 `resource_load_scheduler_test.cc` 是 Chromium Blink 引擎中 `ResourceLoadScheduler` 的单元测试文件。它的主要功能是**验证 `ResourceLoadScheduler` 类的各种行为和逻辑是否正确**。

`ResourceLoadScheduler` 的核心职责是**管理和调度资源加载请求**，例如从网络加载图片、脚本、样式表等资源。它负责决定哪些请求可以立即执行，哪些需要等待，以及请求的执行顺序。

以下是根据测试用例推断出的 `ResourceLoadScheduler` 的主要功能，以及与 JavaScript、HTML、CSS 的关系和使用错误示例：

**`ResourceLoadScheduler` 的主要功能 (通过测试用例推断):**

1. **请求管理 (Request Management):**
   - **接收资源加载请求:** 通过 `Request()` 方法接收客户端（例如，渲染引擎中的其他组件）提交的资源加载请求。每个请求都有一个关联的客户端 (`MockClient`)、优先级 (`ResourceLoadPriority`) 和一些控制选项 (`ThrottleOption`)。
   - **分配请求 ID:**  为每个请求分配一个唯一的 ID (`ResourceLoadScheduler::ClientId`) 用于后续操作。
   - **跟踪未完成的请求:** 内部维护一个队列或类似的数据结构来跟踪所有已提交但尚未完成的请求。

2. **调度 (Scheduling):**
   - **限制并发请求数量:** 通过 `SetOutstandingLimitForTesting()` 方法设置允许同时执行的请求数量上限。这用于模拟资源竞争和控制加载速度。
   - **基于生命周期状态调度:** 根据当前浏览器的生命周期状态 (`scheduler::SchedulingLifecycleState`) 来决定是否允许执行请求。例如，在 `kStopped` 状态下，某些类型的请求可能会被暂停或延迟。
   - **基于节流选项调度:**  根据请求的 `ThrottleOption` 来决定是否可以被节流（暂停）。
     - `kThrottleable`: 可以被节流。
     - `kStoppable`: 可以被停止，但可能在特定状态下恢复。
     - `kCanNotBeStoppedOrThrottled`: 不能被节流或停止，通常用于高优先级或关键资源。
   - **基于优先级调度:**  根据请求的优先级 (`ResourceLoadPriority`) 和内部优先级 (`intra_priority`) 来决定请求的执行顺序。高优先级的请求通常会优先执行。

3. **释放和恢复 (Release and Resume):**
   - **释放请求:** 通过 `Release()` 方法将一个已完成或被取消的请求从调度器中移除。可以选择只释放 (`kReleaseOnly`) 或者释放后尝试调度新的请求 (`kReleaseAndSchedule`).
   - **生命周期状态改变触发恢复:** 当浏览器的生命周期状态发生变化时 (`OnLifecycleStateChanged()`)，调度器会重新评估队列中的请求，并可能恢复被节流的请求。

4. **优先级调整 (Priority Adjustment):**
   - **动态修改优先级:**  通过 `SetPriority()` 方法允许在请求被提交后动态地修改其优先级。

5. **节流策略 (Throttling Policy):**
   - **切换节流策略:** 通过 `LoosenThrottlingPolicy()` 方法可以改变调度器的节流策略，例如从更严格的策略切换到更宽松的策略。

6. **控制台消息 (Console Message):**
   - **报告延迟加载:** 当某些请求被节流过长时间时，调度器可以发送控制台消息进行警告。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`ResourceLoadScheduler` 负责加载网页所需的各种资源，这些资源直接支撑着 JavaScript、HTML 和 CSS 的功能：

* **JavaScript:**
    - 当 HTML 解析器遇到 `<script src="...">` 标签时，会创建一个资源加载请求。`ResourceLoadScheduler` 负责调度这个请求，下载 JavaScript 文件。
    - **示例:**  如果 `ResourceLoadScheduler` 因为达到并发限制而节流了一个 JavaScript 文件的下载请求，那么这个 JavaScript 文件中的代码将不会被立即执行，可能会导致网页交互延迟或功能缺失。

* **HTML:**
    - `<img>` 标签触发图片资源的加载请求。`ResourceLoadScheduler` 调度这些请求来显示网页上的图片。
    - `<link rel="stylesheet" href="...">` 标签触发 CSS 样式表的加载请求。`ResourceLoadScheduler` 负责下载 CSS 文件，这些样式决定了网页的视觉呈现。
    - **示例:**  如果一个重要的 CSS 文件被 `ResourceLoadScheduler` 因为优先级较低而被延迟加载，那么用户可能会先看到一个没有样式的 "白板" 页面，直到 CSS 加载完成。

* **CSS:**
    - CSS 文件中引用的背景图片 (`background-image: url(...)`) 也会触发资源加载请求，由 `ResourceLoadScheduler` 处理。
    - `@import` 规则也会导致额外的 CSS 文件加载，同样由 `ResourceLoadScheduler` 管理。
    - **示例:**  一个 CSS 文件中引用的背景图片如果被 `ResourceLoadScheduler` 节流，可能导致图片在一段时间后才显示出来。

**逻辑推理 (假设输入与输出):**

**假设 1:**

* **输入:**
    * `Scheduler` 的并发限制设置为 1。
    * 提交了两个 `ThrottleOption::kThrottleable` 的请求，优先级相同。
* **输出:**
    * 第一个请求立即执行 (`WasRun()` 返回 `true`)。
    * 第二个请求被放入队列等待 (`WasRun()` 返回 `false`)。
    * 当第一个请求通过 `ReleaseAndSchedule()` 释放后，第二个请求开始执行。

**假设 2:**

* **输入:**
    * `Scheduler` 的生命周期状态设置为 `kStopped`。
    * 提交了一个 `ThrottleOption::kThrottleable` 的请求。
* **输出:**
    * 请求不会立即执行 (`WasRun()` 返回 `false`)，因为它在 `kStopped` 状态下被节流。

**假设 3:**

* **输入:**
    * 提交了一个 `ThrottleOption::kCanNotBeStoppedOrThrottled` 的请求，即使当前并发请求数已达到限制。
* **输出:**
    * 该请求会立即执行 (`WasRun()` 返回 `true`)，因为它不能被节流。

**涉及用户或者编程常见的使用错误 (举例说明):**

1. **多次释放同一个请求 ID:**
   - **代码:**  连续两次调用 `Release(id1)`，其中 `id1` 是同一个请求的 ID。
   - **结果:**  第二次调用 `Release(id1)` 会返回 `false`，表明操作失败。这防止了对同一资源加载状态的错误操作。

2. **释放无效的请求 ID:**
   - **代码:**  调用 `Release(ResourceLoadScheduler::kInvalidClientId)` 或 `Release(一个从未被使用过的 ID)`.
   - **结果:**  `Release()` 方法会返回 `false`，表示无法释放不存在的请求。这避免了程序崩溃或状态不一致。

3. **过度依赖 `kCanNotBeStoppedOrThrottled`:**
   - **场景:**  开发者不恰当地将过多的资源请求设置为 `kCanNotBeStoppedOrThrottled`。
   - **结果:**  这会绕过 `ResourceLoadScheduler` 的节流机制，可能导致网络拥塞、性能下降，甚至影响用户体验。`ResourceLoadScheduler` 的设计意图是让大部分资源加载请求能够被管理和优化。

4. **不理解生命周期状态的影响:**
   - **场景:**  开发者期望在浏览器处于 `kStopped` 状态时，所有资源加载都能正常进行。
   - **结果:**  某些类型的请求在 `kStopped` 状态下会被延迟，开发者需要理解不同生命周期状态对资源加载的影响，并做出相应的处理（例如，在状态改变后重新请求）。

5. **错误地设置并发限制:**
   - **场景:**  开发者将并发限制设置得过低，导致不必要的资源加载延迟。
   - **结果:**  即使网络带宽充足，资源加载也会因为人为的限制而变慢，影响页面加载速度。反之，设置得过高可能导致资源竞争和性能问题。

总而言之，`resource_load_scheduler_test.cc` 通过各种测试用例，详细地验证了 `ResourceLoadScheduler` 在不同场景下的行为，确保它能够有效地管理和调度资源加载请求，从而保障网页的正常加载和性能优化。这些测试也间接地反映了开发者在使用资源加载相关 API 时可能遇到的问题和需要注意的地方。

### 提示词
```
这是目录为blink/renderer/platform/loader/fetch/resource_load_scheduler_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/fetch/resource_load_scheduler.h"

#include <memory>

#include "base/memory/raw_ptr_exclusion.h"
#include "base/test/test_mock_time_task_runner.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/loader/loading_behavior_flag.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/loader/fetch/console_logger.h"
#include "third_party/blink/renderer/platform/loader/fetch/loading_behavior_observer.h"
#include "third_party/blink/renderer/platform/loader/testing/test_resource_fetcher_properties.h"
#include "third_party/blink/renderer/platform/scheduler/test/fake_frame_scheduler.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"

namespace blink {
namespace {

class MockClient final : public GarbageCollected<MockClient>,
                         public ResourceLoadSchedulerClient {
 public:
  // A delegate that can be used to determine the order clients were run in.
  class MockClientDelegate {
    DISALLOW_NEW();

   public:
    MockClientDelegate() = default;
    ~MockClientDelegate() = default;

    void NotifyRun(MockClient* client) { client_order_.push_back(client); }

    // The call order that hte clients ran in.
    const HeapVector<Member<MockClient>>& client_order() {
      return client_order_;
    }

    void Trace(Visitor* visitor) const { visitor->Trace(client_order_); }

   private:
    HeapVector<Member<MockClient>> client_order_;
  };

  ~MockClient() = default;

  void SetDelegate(MockClientDelegate* delegate) { delegate_ = delegate; }

  void Run() override {
    if (delegate_)
      delegate_->NotifyRun(this);
    EXPECT_FALSE(was_run_);
    was_run_ = true;
  }
  bool WasRun() { return was_run_; }

  void Trace(Visitor* visitor) const override {
    ResourceLoadSchedulerClient::Trace(visitor);
    visitor->Trace(console_logger_);
  }

 private:
  Member<DetachableConsoleLogger> console_logger_ =
      MakeGarbageCollected<DetachableConsoleLogger>();
  // RAW_PTR_EXCLUSION: Never allocated by PartitionAlloc (GC'ed type), so
  // there is no benefit to using a raw_ptr, only cost.
  // TODO(crbug.com/348793154): Remove once clang plugin no longer enforces
  // those.
  RAW_PTR_EXCLUSION MockClientDelegate* delegate_;
  bool was_run_ = false;
};

class LoadingBehaviorObserverImpl final
    : public GarbageCollected<LoadingBehaviorObserverImpl>,
      public LoadingBehaviorObserver {
 public:
  void DidObserveLoadingBehavior(LoadingBehaviorFlag behavior) override {
    loading_behavior_flag_ |= behavior;
  }

  int32_t loading_behavior_flag() const { return loading_behavior_flag_; }

 private:
  int32_t loading_behavior_flag_ = 0;
};

class ResourceLoadSchedulerTest : public testing::Test {
 public:
  class MockConsoleLogger final : public GarbageCollected<MockConsoleLogger>,
                                  public ConsoleLogger {
   public:
    bool HasMessage() const { return has_message_; }

   private:
    void AddConsoleMessageImpl(
        mojom::ConsoleMessageSource,
        mojom::ConsoleMessageLevel,
        const String&,
        bool discard_duplicates,
        std::optional<mojom::ConsoleMessageCategory> category) override {
      has_message_ = true;
    }
    void AddConsoleMessageImpl(ConsoleMessage*,
                               bool discard_duplicates) override {
      has_message_ = true;
    }
    bool has_message_ = false;
  };

  using ThrottleOption = ResourceLoadScheduler::ThrottleOption;
  void SetUp() override {
    auto* properties = MakeGarbageCollected<TestResourceFetcherProperties>();
    properties->SetShouldBlockLoadingSubResource(true);
    auto frame_scheduler = std::make_unique<scheduler::FakeFrameScheduler>();
    console_logger_ = MakeGarbageCollected<MockConsoleLogger>();
    loading_observer_behavior_ =
        MakeGarbageCollected<LoadingBehaviorObserverImpl>();
    scheduler_ = MakeGarbageCollected<ResourceLoadScheduler>(
        ResourceLoadScheduler::ThrottlingPolicy::kTight,
        ResourceLoadScheduler::ThrottleOptionOverride::kNone,
        properties->MakeDetachable(), frame_scheduler.get(),
        *MakeGarbageCollected<DetachableConsoleLogger>(console_logger_),
        loading_observer_behavior_.Get());
    Scheduler()->SetOutstandingLimitForTesting(1);
  }
  void TearDown() override { Scheduler()->Shutdown(); }

  MockConsoleLogger* GetConsoleLogger() { return console_logger_; }
  ResourceLoadScheduler* Scheduler() { return scheduler_; }

  bool Release(ResourceLoadScheduler::ClientId client) {
    return Scheduler()->Release(
        client, ResourceLoadScheduler::ReleaseOption::kReleaseOnly,
        ResourceLoadScheduler::TrafficReportHints::InvalidInstance());
  }
  bool ReleaseAndSchedule(ResourceLoadScheduler::ClientId client) {
    return Scheduler()->Release(
        client, ResourceLoadScheduler::ReleaseOption::kReleaseAndSchedule,
        ResourceLoadScheduler::TrafficReportHints::InvalidInstance());
  }

 protected:
  Persistent<MockConsoleLogger> console_logger_;
  Persistent<LoadingBehaviorObserverImpl> loading_observer_behavior_;
  Persistent<ResourceLoadScheduler> scheduler_;
};

TEST_F(ResourceLoadSchedulerTest, StopStoppableRequest) {
  Scheduler()->OnLifecycleStateChanged(
      scheduler::SchedulingLifecycleState::kStopped);
  // A request that disallows throttling should be queued.
  MockClient* client1 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id1 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client1, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kMedium, 0 /* intra_priority */,
                       &id1);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id1);
  EXPECT_FALSE(client1->WasRun());

  // Another request that disallows throttling, but allows stopping should also
  // be queued.
  MockClient* client2 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id2 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client2, ThrottleOption::kStoppable,
                       ResourceLoadPriority::kMedium, 0 /* intra_priority */,
                       &id2);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id2);
  EXPECT_FALSE(client2->WasRun());

  // Another request that disallows throttling and stopping also should be run
  // even it makes the outstanding number reaches to the limit.
  MockClient* client3 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id3 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client3, ThrottleOption::kCanNotBeStoppedOrThrottled,
                       ResourceLoadPriority::kMedium, 0 /* intra_priority */,
                       &id3);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id3);
  EXPECT_TRUE(client3->WasRun());

  // Call Release() with different options just in case.
  EXPECT_TRUE(Release(id1));
  EXPECT_TRUE(ReleaseAndSchedule(id2));
  EXPECT_TRUE(ReleaseAndSchedule(id3));

  // Should not succeed to call with the same ID twice.
  EXPECT_FALSE(Release(id1));

  // Should not succeed to call with the invalid ID or unused ID.
  EXPECT_FALSE(Release(ResourceLoadScheduler::kInvalidClientId));

  EXPECT_FALSE(Release(static_cast<ResourceLoadScheduler::ClientId>(774)));
}

TEST_F(ResourceLoadSchedulerTest, ThrottleThrottleableRequest) {
  Scheduler()->OnLifecycleStateChanged(
      scheduler::SchedulingLifecycleState::kThrottled);

  Scheduler()->SetOutstandingLimitForTesting(0);
  // A request that allows throttling should be queued.
  MockClient* client1 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id1 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client1, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kMedium, 0 /* intra_priority */,
                       &id1);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id1);
  EXPECT_FALSE(client1->WasRun());

  // Another request that disallows throttling also should be run even it makes
  // the outstanding number reaches to the limit.
  MockClient* client2 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id2 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client2, ThrottleOption::kStoppable,
                       ResourceLoadPriority::kMedium, 0 /* intra_priority */,
                       &id2);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id2);
  EXPECT_TRUE(client2->WasRun());

  // Another request that disallows stopping should be run even it makes the
  // outstanding number reaches to the limit.
  MockClient* client3 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id3 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client3, ThrottleOption::kCanNotBeStoppedOrThrottled,
                       ResourceLoadPriority::kMedium, 0 /* intra_priority */,
                       &id3);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id3);
  EXPECT_TRUE(client3->WasRun());

  // Call Release() with different options just in case.
  EXPECT_TRUE(Release(id1));
  EXPECT_TRUE(ReleaseAndSchedule(id2));
  EXPECT_TRUE(ReleaseAndSchedule(id3));

  // Should not succeed to call with the same ID twice.
  EXPECT_FALSE(Release(id1));

  // Should not succeed to call with the invalid ID or unused ID.
  EXPECT_FALSE(Release(ResourceLoadScheduler::kInvalidClientId));

  EXPECT_FALSE(Release(static_cast<ResourceLoadScheduler::ClientId>(774)));
}

TEST_F(ResourceLoadSchedulerTest, Throttled) {
  // The first request should be ran synchronously.
  MockClient* client1 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id1 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client1, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kMedium, 0 /* intra_priority */,
                       &id1);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id1);
  EXPECT_TRUE(client1->WasRun());

  // Another request should be throttled until the first request calls Release.
  MockClient* client2 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id2 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client2, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kMedium, 0 /* intra_priority */,
                       &id2);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id2);
  EXPECT_FALSE(client2->WasRun());

  // Two more requests.
  MockClient* client3 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id3 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client3, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kMedium, 0 /* intra_priority */,
                       &id3);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id3);
  EXPECT_FALSE(client3->WasRun());

  MockClient* client4 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id4 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client4, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kMedium, 0 /* intra_priority */,
                       &id4);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id4);
  EXPECT_FALSE(client4->WasRun());

  // Call Release() to run the second request.
  EXPECT_TRUE(ReleaseAndSchedule(id1));
  EXPECT_TRUE(client2->WasRun());

  // Call Release() with kReleaseOnly should not run the third and the fourth
  // requests.
  EXPECT_TRUE(Release(id2));
  EXPECT_FALSE(client3->WasRun());
  EXPECT_FALSE(client4->WasRun());

  // Should be able to call Release() for a client that hasn't run yet. This
  // should run another scheduling to run the fourth request.
  EXPECT_TRUE(ReleaseAndSchedule(id3));
  EXPECT_TRUE(client4->WasRun());
}

TEST_F(ResourceLoadSchedulerTest, Unthrottle) {
  // Push three requests.
  MockClient* client1 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id1 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client1, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kMedium, 0 /* intra_priority */,
                       &id1);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id1);
  EXPECT_TRUE(client1->WasRun());

  MockClient* client2 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id2 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client2, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kMedium, 0 /* intra_priority */,
                       &id2);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id2);
  EXPECT_FALSE(client2->WasRun());

  MockClient* client3 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id3 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client3, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kMedium, 0 /* intra_priority */,
                       &id3);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id3);
  EXPECT_FALSE(client3->WasRun());

  // Allows to pass all requests.
  Scheduler()->SetOutstandingLimitForTesting(3);
  EXPECT_TRUE(client2->WasRun());
  EXPECT_TRUE(client3->WasRun());

  // Release all.
  EXPECT_TRUE(Release(id3));
  EXPECT_TRUE(Release(id2));
  EXPECT_TRUE(Release(id1));
}

TEST_F(ResourceLoadSchedulerTest, Stopped) {
  // Push three requests.
  MockClient* client1 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id1 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client1, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kMedium, 0 /* intra_priority */,
                       &id1);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id1);
  EXPECT_TRUE(client1->WasRun());

  MockClient* client2 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id2 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client2, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kMedium, 0 /* intra_priority */,
                       &id2);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id2);
  EXPECT_FALSE(client2->WasRun());

  MockClient* client3 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id3 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client3, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kMedium, 0 /* intra_priority */,
                       &id3);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id3);
  EXPECT_FALSE(client3->WasRun());

  // Setting outstanding_limit_ to 0 in ThrottlingState::kStopped, prevents
  // further requests.
  Scheduler()->SetOutstandingLimitForTesting(0);
  EXPECT_FALSE(client2->WasRun());
  EXPECT_FALSE(client3->WasRun());

  // Calling Release() still does not run the second request.
  EXPECT_TRUE(ReleaseAndSchedule(id1));
  EXPECT_FALSE(client2->WasRun());
  EXPECT_FALSE(client3->WasRun());

  // Release all.
  EXPECT_TRUE(Release(id3));
  EXPECT_TRUE(Release(id2));
}

TEST_F(ResourceLoadSchedulerTest, PriorityIsConsidered) {
  // This tests the request limiting logic in the scheduler for
  // the tight-mode and regular-mode limits as well as the
  // special-casing for medium-priority requests.

  // Allow 1 overall request as well as 1 special-case medium request
  // while blocking anly low-priority requests (starts in tight mode)
  Scheduler()->SetOutstandingLimitForTesting(
      0 /* tight_limit */, 1 /* normal_limit */, 1 /* tight_medium_limit */);

  MockClient* client1 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id1 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client1, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kLowest, 10 /* intra_priority */,
                       &id1);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id1);

  MockClient* client2 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id2 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client2, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kLow, 1 /* intra_priority */,
                       &id2);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id2);

  MockClient* client3 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id3 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client3, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kLow, 3 /* intra_priority */,
                       &id3);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id3);

  MockClient* client4 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id4 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client4, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kHigh, 0 /* intra_priority */,
                       &id4);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id4);

  MockClient* client5 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id5 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client5, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kMedium, 0 /* intra_priority */,
                       &id5);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id5);

  MockClient* client6 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id6 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client6, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kMedium, 0 /* intra_priority */,
                       &id6);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id6);

  // Expect that all 3 kLow requests are held, the one kHigh request
  // is sent by the normal limit and one of the kMedium requests
  // was sent using the medium-specific limit.
  EXPECT_FALSE(client1->WasRun()); /* kLowest */
  EXPECT_FALSE(client2->WasRun()); /* kLow intra=1 */
  EXPECT_FALSE(client3->WasRun()); /* kLow intra=3 */
  EXPECT_TRUE(client4->WasRun());  /* kHigh - Newly run */
  EXPECT_TRUE(client5->WasRun());  /* kMedium - Newly run */
  EXPECT_FALSE(client6->WasRun()); /* kMedium */

  // Calling Release() on kMedium schedules another one.
  EXPECT_TRUE(ReleaseAndSchedule(id5));
  EXPECT_FALSE(client1->WasRun()); /* kLowest */
  EXPECT_FALSE(client2->WasRun()); /* kLow intra=1 */
  EXPECT_FALSE(client3->WasRun()); /* kLow intra=3 */
  // 4 and 5 were already run and checked
  EXPECT_TRUE(client6->WasRun()); /* kMedium - Newly run */

  // Calling Release() on the last kMedium does not schedule non-medium.
  EXPECT_TRUE(ReleaseAndSchedule(id6));
  EXPECT_FALSE(client1->WasRun()); /* kLowest */
  EXPECT_FALSE(client2->WasRun()); /* kLow intra=1 */
  EXPECT_FALSE(client3->WasRun()); /* kLow intra=3 */
  // 4-6 have already run and been run and validated

  // Increasing the limit to 2 should allow another low-priority request
  // through, in order of priority (client 3 with the highest intra-priority).
  Scheduler()->SetOutstandingLimitForTesting(2);
  EXPECT_FALSE(client1->WasRun()); /* kLowest */
  EXPECT_FALSE(client2->WasRun()); /* kLow intra=1 */
  EXPECT_TRUE(client3->WasRun());  /* kLow intra=3 - Newly run */

  // Increasing the limit to 3 should allow another low-priority request
  // through, in order of priority (client 2).
  Scheduler()->SetOutstandingLimitForTesting(3);
  EXPECT_FALSE(client1->WasRun()); /* kLowest */
  EXPECT_TRUE(client2->WasRun());  /* kLow intra=1 - Newly run */
  // 3-6 have already run and been run and validated

  // Increasing the limit to 4 should allow the final (lowest-priority)
  // request through.
  Scheduler()->SetOutstandingLimitForTesting(4);
  EXPECT_TRUE(client1->WasRun());

  // Release the rest.
  EXPECT_TRUE(Release(id4));
  EXPECT_TRUE(Release(id3));
  EXPECT_TRUE(Release(id2));
  EXPECT_TRUE(Release(id1));
}

TEST_F(ResourceLoadSchedulerTest, AllowedRequestsRunInPriorityOrder) {
  Scheduler()->OnLifecycleStateChanged(
      scheduler::SchedulingLifecycleState::kStopped);
  Scheduler()->SetOutstandingLimitForTesting(0);

  MockClient::MockClientDelegate delegate;
  // Push two requests.
  MockClient* client1 = MakeGarbageCollected<MockClient>();
  MockClient* client2 = MakeGarbageCollected<MockClient>();

  client1->SetDelegate(&delegate);
  client2->SetDelegate(&delegate);

  ResourceLoadScheduler::ClientId id1 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client1, ThrottleOption::kStoppable,
                       ResourceLoadPriority::kLowest, 10 /* intra_priority */,
                       &id1);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id1);

  ResourceLoadScheduler::ClientId id2 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client2, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kHigh, 1 /* intra_priority */,
                       &id2);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id2);

  EXPECT_FALSE(client1->WasRun());
  EXPECT_FALSE(client2->WasRun());

  Scheduler()->SetOutstandingLimitForTesting(1);

  Scheduler()->OnLifecycleStateChanged(
      scheduler::SchedulingLifecycleState::kThrottled);

  EXPECT_TRUE(client1->WasRun());
  EXPECT_TRUE(client2->WasRun());

  // Release all.
  EXPECT_TRUE(Release(id1));
  EXPECT_TRUE(Release(id2));

  // Verify high priority request ran first.
  auto& order = delegate.client_order();
  EXPECT_EQ(order[0], client2);
  EXPECT_EQ(order[1], client1);
}

TEST_F(ResourceLoadSchedulerTest, StoppableRequestResumesWhenThrottled) {
  Scheduler()->OnLifecycleStateChanged(
      scheduler::SchedulingLifecycleState::kStopped);
  // Push two requests.
  MockClient* client1 = MakeGarbageCollected<MockClient>();

  Scheduler()->SetOutstandingLimitForTesting(0);

  ResourceLoadScheduler::ClientId id1 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client1, ThrottleOption::kStoppable,
                       ResourceLoadPriority::kLowest, 10 /* intra_priority */,
                       &id1);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id1);

  MockClient* client2 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id2 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client2, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kHigh, 1 /* intra_priority */,
                       &id2);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id2);

  MockClient* client3 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id3 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client3, ThrottleOption::kStoppable,
                       ResourceLoadPriority::kLowest, 10 /* intra_priority */,
                       &id3);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id3);

  EXPECT_FALSE(client1->WasRun());
  EXPECT_FALSE(client2->WasRun());
  EXPECT_FALSE(client3->WasRun());

  Scheduler()->OnLifecycleStateChanged(
      scheduler::SchedulingLifecycleState::kThrottled);

  EXPECT_TRUE(client1->WasRun());
  EXPECT_FALSE(client2->WasRun());
  EXPECT_TRUE(client3->WasRun());

  Scheduler()->SetOutstandingLimitForTesting(1);

  EXPECT_TRUE(client1->WasRun());
  EXPECT_TRUE(client2->WasRun());
  EXPECT_TRUE(client3->WasRun());

  // Release all.
  EXPECT_TRUE(Release(id1));
  EXPECT_TRUE(Release(id2));
  EXPECT_TRUE(Release(id3));
}

TEST_F(ResourceLoadSchedulerTest, SetPriority) {
  // Push three requests.
  MockClient* client1 = MakeGarbageCollected<MockClient>();

  // Allows one kHigh priority request by limits below.
  Scheduler()->SetOutstandingLimitForTesting(0, 1);

  ResourceLoadScheduler::ClientId id1 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client1, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kLowest, 0 /* intra_priority */,
                       &id1);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id1);

  MockClient* client2 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id2 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client2, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kLow, 5 /* intra_priority */,
                       &id2);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id2);

  MockClient* client3 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id3 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client3, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kLow, 10 /* intra_priority */,
                       &id3);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id3);

  EXPECT_FALSE(client1->WasRun());
  EXPECT_FALSE(client2->WasRun());
  EXPECT_FALSE(client3->WasRun());

  Scheduler()->SetPriority(id1, ResourceLoadPriority::kHigh, 0);

  EXPECT_TRUE(client1->WasRun());
  EXPECT_FALSE(client2->WasRun());
  EXPECT_FALSE(client3->WasRun());

  Scheduler()->SetPriority(id3, ResourceLoadPriority::kLow, 2);

  EXPECT_TRUE(client1->WasRun());
  EXPECT_FALSE(client2->WasRun());
  EXPECT_FALSE(client3->WasRun());

  // Loosen the policy to adopt the normal limit for all. Two requests
  // regardless of priority can be granted (including the in-flight high
  // priority request).
  Scheduler()->LoosenThrottlingPolicy();
  Scheduler()->SetOutstandingLimitForTesting(0, 2);

  EXPECT_TRUE(client1->WasRun());
  EXPECT_TRUE(client2->WasRun());
  EXPECT_FALSE(client3->WasRun());

  // kHigh priority does not help the third request here.
  Scheduler()->SetPriority(id3, ResourceLoadPriority::kHigh, 0);

  EXPECT_TRUE(client1->WasRun());
  EXPECT_TRUE(client2->WasRun());
  EXPECT_FALSE(client3->WasRun());

  // Release all.
  EXPECT_TRUE(Release(id3));
  EXPECT_TRUE(Release(id2));
  EXPECT_TRUE(Release(id1));
}

TEST_F(ResourceLoadSchedulerTest, LoosenThrottlingPolicy) {
  MockClient* client1 = MakeGarbageCollected<MockClient>();

  Scheduler()->SetOutstandingLimitForTesting(0, 0);

  ResourceLoadScheduler::ClientId id1 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client1, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kLowest, 0 /* intra_priority */,
                       &id1);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id1);

  MockClient* client2 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id2 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client2, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kLowest, 0 /* intra_priority */,
                       &id2);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id2);

  MockClient* client3 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id3 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client3, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kLowest, 0 /* intra_priority */,
                       &id3);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id3);

  MockClient* client4 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id4 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client4, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kLowest, 0 /* intra_priority */,
                       &id4);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id4);

  Scheduler()->SetPriority(id2, ResourceLoadPriority::kLow, 0);
  Scheduler()->SetPriority(id3, ResourceLoadPriority::kLow, 0);
  Scheduler()->SetPriority(id4, ResourceLoadPriority::kMedium, 0);

  // As the policy is |kTight|, |kMedium| is throttled.
  EXPECT_FALSE(client1->WasRun());
  EXPECT_FALSE(client2->WasRun());
  EXPECT_FALSE(client3->WasRun());
  EXPECT_FALSE(client4->WasRun());

  Scheduler()->SetOutstandingLimitForTesting(0, 2);

  // The initial scheduling policy is |kTight|, setting the
  // outstanding limit for the normal mode doesn't take effect.
  EXPECT_FALSE(client1->WasRun());
  EXPECT_FALSE(client2->WasRun());
  EXPECT_FALSE(client3->WasRun());
  EXPECT_FALSE(client4->WasRun());

  // Now let's tighten the limit again.
  Scheduler()->SetOutstandingLimitForTesting(0, 0);

  // ...and change the scheduling policy to |kNormal|.
  Scheduler()->LoosenThrottlingPolicy();

  EXPECT_FALSE(client1->WasRun());
  EXPECT_FALSE(client2->WasRun());
  EXPECT_FALSE(client3->WasRun());
  EXPECT_FALSE(client4->WasRun());

  Scheduler()->SetOutstandingLimitForTesting(0, 2);

  EXPECT_FALSE(client1->WasRun());
  EXPECT_TRUE(client2->WasRun());
  EXPECT_FALSE(client3->WasRun());
  EXPECT_TRUE(client4->WasRun());

  // Release all.
  EXPECT_TRUE(Release(id4));
  EXPECT_TRUE(Release(id3));
  EXPECT_TRUE(Release(id2));
  EXPECT_TRUE(Release(id1));
}

TEST_F(ResourceLoadSchedulerTest, ConsoleMessage) {
  auto test_task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();

  // Use a mock clock to control the time.
  Scheduler()->SetClockForTesting(test_task_runner->GetMockClock());

  Scheduler()->SetOutstandingLimitForTesting(0, 0);
  Scheduler()->OnLifecycleStateChanged(
      scheduler::SchedulingLifecycleState::kThrottled);

  // Push two requests into the queue.
  MockClient* client1 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id1 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client1, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kLowest, 0 /* intra_priority */,
                       &id1);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id1);
  EXPECT_FALSE(client1->WasRun());

  MockClient* client2 = MakeGarbageCollected<MockClient>();
  ResourceLoadScheduler::ClientId id2 = ResourceLoadScheduler::kInvalidClientId;
  Scheduler()->Request(client2, ThrottleOption::kThrottleable,
                       ResourceLoadPriority::kLowest, 0 /* intra_priority */,
                       &id2);
  EXPECT_NE(ResourceLoadScheduler::kInvalidClientId, id2);
  EXPECT_FALSE(client2->WasRun());

  // Cancel the first request
  EXPECT_TRUE(Release(id1));

  // Advance current time a little and triggers an life cycle event, but it
  // still won't awake the warning logic.
  test_task_runner->FastForwardBy(base::Seconds(50));
  Scheduler()->OnLifecycleStateChanged(
      scheduler::SchedulingLifecycleState::kNotThrottled);
  EXPECT_FALSE(GetConsoleLogger()->HasMessage());
  Scheduler()->OnLifecycleStateChanged(
      scheduler::SchedulingLifecycleState::kThrottled);

  // Modify current time to awake the console warning logic, and the second
  // client should be used for console logging.
  test_task_runner->FastForwardBy(base::Seconds(15));
  Scheduler()->OnLifecycleStateChanged(
      scheduler::SchedulingLifecycleState::kNotThrottled);
  EXPECT_TRUE(GetConsoleLogger()->HasMessage());
  EXPECT_TRUE(Release(id2));

  // Reset the reference to ensure scheduler won't keep a reference to the
  // destroyed clock.
  Scheduler()->SetClockForTesting(nullptr);
}

}  // namespace
}  // namespace blink
```