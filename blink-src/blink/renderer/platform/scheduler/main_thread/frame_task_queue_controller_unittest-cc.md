Response: Let's break down the thought process for analyzing the provided C++ test file.

1. **Identify the Core Purpose:** The filename `frame_task_queue_controller_unittest.cc` immediately suggests this file contains unit tests for the `FrameTaskQueueController` class. The "unittest" suffix is a strong indicator.

2. **Understand the Tested Class:**  The `#include` directives confirm this. We see `#include "third_party/blink/renderer/platform/scheduler/main_thread/frame_task_queue_controller.h"`. This tells us the tests are focused on the functionalities provided by `FrameTaskQueueController`.

3. **Scan for Test Fixtures:** The code defines a test fixture: `class FrameTaskQueueControllerTest : public testing::Test, public FrameTaskQueueController::Delegate`. This structure is standard for Google Test. We know that each `TEST_F` will use an instance of this fixture. The inheritance from `FrameTaskQueueController::Delegate` suggests that the test fixture is also acting as a delegate to observe or interact with the `FrameTaskQueueController`.

4. **Examine Setup and Teardown:** The `SetUp()` and `TearDown()` methods are crucial. They reveal the dependencies and initialization steps required for testing. We see the creation of:
    * `MainThreadSchedulerImpl`
    * `AgentGroupScheduler`
    * `PageScheduler`
    * `FrameScheduler`
    * `FrameTaskQueueController` (the class under test)
   This dependency chain hints at the role of `FrameTaskQueueController` within the broader scheduling hierarchy. `TearDown()` ensures proper cleanup.

5. **Analyze Helper Methods:**  Methods like `LoadingTaskQueue()`, `LoadingControlTaskQueue()`, and `ThrottleableTaskQueue()` are clearly utility methods for easily retrieving specific types of task queues based on their `QueueTraits`. This points to the ability of `FrameTaskQueueController` to create and manage different kinds of task queues. The `GetTaskQueue(QueueTraits)` method reinforces this.

6. **Focus on Individual Tests:** Now, look at each `TEST_F`:

    * **`CreateAllTaskQueues`:**  This test verifies that the `FrameTaskQueueController` can create various default task queues based on different `QueueTraits`. It checks for uniqueness and ensures the delegate is notified of creation. This directly relates to the core function of the controller.

    * **`NonWebSchedulingTaskQueueWebSchedulingPriorityNullopt`:** This checks the default behavior for non-web-scheduling task queues, confirming they don't have a web scheduling priority.

    * **`AddWebSchedulingTaskQueues`:**  This tests the ability to create task queues specifically for web scheduling with different priorities.

    * **`RemoveWebSchedulingTaskQueues`:**  This verifies the functionality to remove web scheduling task queues.

    * **`AddMultipleSamePriorityWebSchedulingTaskQueues`:** This ensures that creating multiple web scheduling queues with the same priority results in distinct queue objects.

    * **`QueueTypeFromQueueTraits`:**  This test confirms that the `FrameTaskQueueController` correctly assigns `QueueType` enums based on the `QueueTraits` used to create the queue.

    * **`TaskQueueCreationFromQueueTraitsTest`:** This is a parameterized test that exhaustively checks the creation and retrieval of task queues for various combinations of `QueueTraits` and `PrioritisationType`. This is a thorough test covering a wide range of configurations.

7. **Identify Relationships to Web Technologies:**  The presence of "WebSchedulingPriority" and "WebSchedulingQueueType" strongly suggests a connection to how Blink prioritizes tasks related to rendering web pages. Think about how JavaScript execution, HTML parsing, and CSS processing are all tasks that need scheduling. Different priorities might be assigned to different types of these tasks.

8. **Infer Logic and Assumptions:** Based on the tests, we can infer:
    * `FrameTaskQueueController` manages the creation and storage of `MainThreadTaskQueue` objects.
    * Task queues have associated `QueueTraits` that define their properties (e.g., can be throttled, deferred, paused).
    * Different prioritisation types exist for task queues.
    * Web-specific scheduling priorities are handled.
    * The delegate pattern is used to notify observers about task queue creation.

9. **Consider User/Programming Errors:**  Think about common mistakes developers might make when interacting with a system like this. For example:
    * Requesting a task queue with inconsistent or contradictory traits.
    * Forgetting to remove web scheduling task queues when they are no longer needed.
    * Incorrectly assuming the existence of a specific task queue without checking.

10. **Structure the Explanation:** Finally, organize the findings into a clear and structured explanation, covering the functionality, relationships to web technologies, logic/assumptions, and potential errors. Use examples to illustrate the concepts and connections to JavaScript, HTML, and CSS.

Self-Correction/Refinement during the process:

* **Initial thought:**  "This is just about creating task queues."
* **Correction:**  The tests reveal more than just creation. They also cover retrieval, removal, setting priorities, and the relationship between `QueueTraits` and `QueueType`.

* **Initial thought:** "The delegate pattern isn't important."
* **Correction:** The `OnTaskQueueCreated` method and the `task_queue_created_count_` variable show that the delegate pattern is used for tracking the creation of task queues, which is a significant aspect of the controller's behavior.

* **Initial thought:**  "The connection to web tech is vague."
* **Refinement:** By focusing on the "WebSchedulingPriority" and "WebSchedulingQueueType" concepts and thinking about the types of tasks involved in rendering a web page, a clearer picture of the relationship emerges. Examples of JavaScript execution, layout, and rendering become relevant.
这个C++源代码文件 `frame_task_queue_controller_unittest.cc` 是 Chromium Blink 引擎的一部分，它专门用于测试 `FrameTaskQueueController` 类的功能。`FrameTaskQueueController` 的主要职责是管理与特定渲染帧（frame）关联的任务队列。

以下是该文件的主要功能点：

**1. 单元测试框架:**  该文件使用 Google Test 框架 (`testing/gtest/include/gtest/gtest.h`) 来编写和执行单元测试。这表明其主要目的是验证 `FrameTaskQueueController` 类的各种方法和行为是否符合预期。

**2. 测试 `FrameTaskQueueController` 的核心功能:**  文件中定义了名为 `FrameTaskQueueControllerTest` 的测试 fixture，它继承自 `testing::Test` 并实现了 `FrameTaskQueueController::Delegate` 接口。这个 fixture 提供了测试 `FrameTaskQueueController` 所需的环境和辅助方法。

**3. 任务队列的创建和管理:**  测试用例主要关注 `FrameTaskQueueController` 创建和管理不同类型任务队列的能力。这些任务队列由 `MainThreadTaskQueue` 类表示，并且具有不同的特性（通过 `QueueTraits` 定义），例如是否可以被暂停、冻结、延迟、节流等。

**4. 测试不同类型的任务队列:**  测试用例针对以下几种类型的任务队列进行了测试：
    * **Loading Task Queue:**  用于处理页面加载相关的任务。
    * **Loading Control Task Queue:** 用于处理加载控制相关的任务。
    * **Throttleable Task Queue:** 可以被节流的任务队列。
    * **Web Scheduling Task Queues:**  具有特定 Web 调度优先级的任务队列。
    * 基于各种 `QueueTraits` 组合创建的任务队列。

**5. 测试 Web 调度优先级:**  专门测试了创建和管理具有 Web 调度优先级的任务队列，例如 `kUserBlockingPriority`、`kUserVisiblePriority` 和 `kBackgroundPriority`。

**6. 测试任务队列的添加和移除:**  测试了如何添加新的 Web 调度任务队列，以及如何移除已存在的 Web 调度任务队列。

**7. 测试相同优先级 Web 调度任务队列的创建:**  验证了可以创建多个具有相同 Web 调度优先级的任务队列，并且它们是不同的实例。

**8. 测试 `QueueType` 的分配:**  验证了根据 `QueueTraits` 创建的任务队列会被分配正确的 `QueueType` 枚举值。

**9. 模拟和隔离依赖:**  测试环境通过 `base::test::TaskEnvironment` 来模拟消息循环和时间，这使得测试可以独立运行，不依赖真实的系统环境。

**与 JavaScript, HTML, CSS 的关系：**

`FrameTaskQueueController` 在 Blink 渲染引擎中扮演着至关重要的角色，它直接关系到 JavaScript 的执行、HTML 的解析和渲染、CSS 的计算和应用等核心功能。

* **JavaScript 执行:** 当 JavaScript 代码需要执行时，相关的任务会被添加到主线程的任务队列中。`FrameTaskQueueController` 负责管理这些任务队列，并根据任务的优先级和队列的特性进行调度。例如，用户交互触发的事件（如点击）通常会进入高优先级的任务队列，以便快速响应。

    **举例说明:**  假设用户点击一个按钮，触发了一个 JavaScript 事件处理函数。这个事件处理函数会被封装成一个任务，并根据其重要性（通常是用户阻塞级别）被添加到 `FrameTaskQueueController` 管理的某个任务队列中。主线程调度器会从这些队列中取出任务并执行，从而执行 JavaScript 代码。

* **HTML 解析和渲染:**  当浏览器加载 HTML 文档时，解析器会逐步解析 HTML 结构并构建 DOM 树。这个过程涉及到多个异步任务，例如加载外部资源、处理脚本等。`FrameTaskQueueController` 负责管理这些与 HTML 解析和渲染相关的任务队列。加载任务队列 (`LoadingTaskQueue`) 就是用于处理这些任务的。

    **举例说明:** 当浏览器下载 HTML 文件时，解析器开始工作并将 HTML 内容转换为 DOM 节点。这个过程中，如果遇到 `<img>` 标签，浏览器会发起一个新的网络请求去下载图片。下载图片的任务会被添加到 `FrameTaskQueueController` 管理的加载任务队列中。当图片下载完成后，相应的回调任务会被调度执行，以便将图片渲染到页面上。

* **CSS 计算和应用:**  CSS 样式规则需要被解析、计算并应用到 DOM 树上，以确定最终的渲染效果。这个过程也涉及到多个任务，例如解析 CSS 文件、匹配 CSS 选择器、计算样式属性等。`FrameTaskQueueController` 管理着与这些 CSS 处理相关的任务队列。

    **举例说明:**  当浏览器加载一个包含 CSS 规则的样式表时，CSS 解析器会解析这些规则并构建 CSSOM 树。解析和应用 CSS 规则的任务会被添加到 `FrameTaskQueueController` 管理的任务队列中。例如，计算元素最终样式（包括继承、层叠等）的任务需要在主线程上调度执行。

**逻辑推理的假设输入与输出：**

该文件主要是单元测试，侧重于验证代码行为的正确性，而不是进行复杂的逻辑推理。但是，我们可以从测试用例中推断出一些假设输入和预期输出：

**假设输入（针对 `CreateAllTaskQueues` 测试）:**

* 调用 `FrameTaskQueueController` 的方法来请求不同 `QueueTraits` 的任务队列。

**预期输出:**

* 对于每种 `QueueTraits` 的请求，`FrameTaskQueueController` 应该返回一个对应的 `MainThreadTaskQueue` 实例。
* 所有请求的任务队列都应该被创建并记录在内部数据结构中。
* `FrameTaskQueueController::Delegate` 的 `OnTaskQueueCreated` 方法应该被调用，并且调用次数与创建的任务队列数量一致。

**用户或编程常见的使用错误举例：**

虽然 `FrameTaskQueueController` 是 Blink 内部的组件，开发者通常不会直接使用它，但理解其背后的原理可以帮助避免一些与性能和渲染相关的错误。

1. **过度使用高优先级任务:** 如果大量的任务都被标记为高优先级（例如用户阻塞级别），可能会导致主线程过于繁忙，影响页面渲染的流畅性和用户交互的响应速度。

    **例子:**  一个开发者在 JavaScript 中对所有操作都使用同步的方式或者频繁地使用高优先级的任务调度，可能会阻塞主线程，导致页面卡顿。

2. **长时间运行的任务阻塞主线程:**  如果在主线程的任务队列中存在耗时很长的任务，例如复杂的计算或者大量的 DOM 操作，会导致后续的任务被延迟执行，影响用户体验。

    **例子:**  一个 JavaScript 动画循环中，如果动画计算过于复杂，并且在每次刷新时都执行大量的 DOM 操作，可能会导致帧率下降，动画不流畅。

3. **不必要的任务调度:**  如果没有合理地组织和调度任务，可能会导致不必要的任务被执行，浪费资源并降低性能。

    **例子:**  在某些情况下，开发者可能会在短时间内重复调度相同的任务，而没有进行必要的去重或合并处理。

4. **错误地假设任务队列的执行顺序:**  虽然任务队列通常按照优先级和先进先出的原则执行，但在复杂的调度场景下，任务的实际执行顺序可能会受到其他因素的影响。开发者不应该做出过于绝对的假设。

    **例子:**  开发者可能会错误地假设一个通过 `postTask` 提交的任务会立即在当前执行的代码之后运行，但实际上它会被添加到任务队列中，并在稍后的某个时间点被调度执行。

总而言之，`frame_task_queue_controller_unittest.cc` 通过详尽的单元测试，确保了 `FrameTaskQueueController` 能够正确地创建、管理和调度各种类型的任务队列，这对于 Blink 渲染引擎的稳定性和性能至关重要，并且间接地影响着 JavaScript、HTML 和 CSS 的处理效率。

Prompt: 
```
这是目录为blink/renderer/platform/scheduler/main_thread/frame_task_queue_controller_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/scheduler/main_thread/frame_task_queue_controller.h"

#include <memory>
#include <optional>
#include <utility>

#include "base/containers/contains.h"
#include "base/functional/bind.h"
#include "base/memory/scoped_refptr.h"
#include "base/run_loop.h"
#include "base/task/sequence_manager/task_queue.h"
#include "base/task/sequence_manager/test/sequence_manager_for_test.h"
#include "base/test/task_environment.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/platform/scheduler/common/task_priority.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/frame_scheduler_impl.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/main_thread_scheduler_impl.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/main_thread_task_queue.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/page_scheduler_impl.h"
#include "third_party/blink/renderer/platform/scheduler/public/web_scheduling_priority.h"
#include "third_party/blink/renderer/platform/scheduler/public/web_scheduling_queue_type.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"

using base::sequence_manager::TaskQueue;
using QueueType = blink::scheduler::MainThreadTaskQueue::QueueType;
using QueueTraits = blink::scheduler::MainThreadTaskQueue::QueueTraits;

namespace blink {
namespace scheduler {

class FrameTaskQueueControllerTest : public testing::Test,
                                     public FrameTaskQueueController::Delegate {
 public:
  FrameTaskQueueControllerTest()
      : task_environment_(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME,
            base::test::TaskEnvironment::ThreadPoolExecutionMode::QUEUED),
        task_queue_created_count_(0) {}
  FrameTaskQueueControllerTest(const FrameTaskQueueControllerTest&) = delete;
  FrameTaskQueueControllerTest& operator=(const FrameTaskQueueControllerTest&) =
      delete;

  ~FrameTaskQueueControllerTest() override = default;

  void SetUp() override {
    auto settings = base::sequence_manager::SequenceManager::Settings::Builder()
                        .SetPrioritySettings(CreatePrioritySettings())
                        .Build();
    scheduler_ = std::make_unique<MainThreadSchedulerImpl>(
        base::sequence_manager::SequenceManagerForTest::Create(
            nullptr, task_environment_.GetMainThreadTaskRunner(),
            task_environment_.GetMockTickClock(), std::move(settings)));
    agent_group_scheduler_ = scheduler_->CreateAgentGroupScheduler();
    page_scheduler_ = agent_group_scheduler_->CreatePageScheduler(nullptr);
    frame_scheduler_ = page_scheduler_->CreateFrameScheduler(
        nullptr, /*is_in_embedded_frame_tree=*/false,
        FrameScheduler::FrameType::kSubframe);
    frame_task_queue_controller_ = std::make_unique<FrameTaskQueueController>(
        scheduler_.get(),
        static_cast<FrameSchedulerImpl*>(frame_scheduler_.get()), this);
  }

  void TearDown() override {
    frame_task_queue_controller_.reset();
    frame_scheduler_.reset();
    page_scheduler_.reset();
    agent_group_scheduler_ = nullptr;
    scheduler_->Shutdown();
    scheduler_.reset();
  }

  // FrameTaskQueueController::Delegate implementation.
  void OnTaskQueueCreated(MainThreadTaskQueue* task_queue,
                          TaskQueue::QueueEnabledVoter* voter) override {
    ++task_queue_created_count_;
  }

 protected:
  scoped_refptr<MainThreadTaskQueue> LoadingTaskQueue() const {
    return frame_task_queue_controller_->GetTaskQueue(QueueTraits()
        .SetCanBePaused(true)
        .SetCanBeFrozen(true)
        .SetCanBeDeferred(true)
        .SetPrioritisationType(
            QueueTraits::PrioritisationType::kLoading));
  }

  scoped_refptr<MainThreadTaskQueue> LoadingControlTaskQueue() const {
    return frame_task_queue_controller_->GetTaskQueue(QueueTraits()
        .SetCanBePaused(true)
        .SetCanBeFrozen(true)
        .SetCanBeDeferred(true)
        .SetPrioritisationType(
            QueueTraits::PrioritisationType::kLoadingControl));
  }

  scoped_refptr<MainThreadTaskQueue> ThrottleableTaskQueue() const {
    return frame_task_queue_controller_->GetTaskQueue(
        QueueTraits()
            .SetCanBeThrottled(true)
            .SetCanBeFrozen(true)
            .SetCanBeDeferred(true)
            .SetCanBePaused(true)
            .SetCanRunWhenVirtualTimePaused(false));
  }

  scoped_refptr<MainThreadTaskQueue> GetTaskQueue(
      QueueTraits queue_traits) const {
    return frame_task_queue_controller_->GetTaskQueue(queue_traits);
  }

  size_t task_queue_created_count() const { return task_queue_created_count_; }

 protected:
  base::test::TaskEnvironment task_environment_;
  std::unique_ptr<MainThreadSchedulerImpl> scheduler_;
  Persistent<AgentGroupScheduler> agent_group_scheduler_;
  std::unique_ptr<PageScheduler> page_scheduler_;
  std::unique_ptr<FrameScheduler> frame_scheduler_;
  std::unique_ptr<FrameTaskQueueController> frame_task_queue_controller_;

 private:
  size_t task_queue_created_count_;
};

TEST_F(FrameTaskQueueControllerTest, CreateAllTaskQueues) {
  enum class QueueCheckResult { kDidNotSeeQueue, kDidSeeQueue };

  WTF::HashMap<scoped_refptr<MainThreadTaskQueue>, QueueCheckResult>
      all_task_queues;

  scoped_refptr<MainThreadTaskQueue> task_queue = LoadingTaskQueue();
  EXPECT_FALSE(all_task_queues.Contains(task_queue));
  all_task_queues.insert(task_queue.get(), QueueCheckResult::kDidNotSeeQueue);
  EXPECT_EQ(all_task_queues.size(), task_queue_created_count());

  task_queue = LoadingControlTaskQueue();
  EXPECT_FALSE(all_task_queues.Contains(task_queue));
  all_task_queues.insert(task_queue.get(), QueueCheckResult::kDidNotSeeQueue);
  EXPECT_EQ(all_task_queues.size(), task_queue_created_count());

  // Create the 4 default task queues used by FrameSchedulerImpl.
  task_queue = GetTaskQueue(QueueTraits()
                                .SetCanBeThrottled(true)
                                .SetCanBeDeferred(true)
                                .SetCanBeFrozen(true)
                                .SetCanBePaused(true)
                                .SetCanRunWhenVirtualTimePaused(false));
  EXPECT_FALSE(all_task_queues.Contains(task_queue));
  all_task_queues.insert(task_queue.get(), QueueCheckResult::kDidNotSeeQueue);
  EXPECT_EQ(all_task_queues.size(), task_queue_created_count());

  task_queue = GetTaskQueue(QueueTraits()
                                .SetCanBeDeferred(true)
                                .SetCanBePaused(true)
                                .SetCanRunWhenVirtualTimePaused(false));
  EXPECT_FALSE(all_task_queues.Contains(task_queue));
  all_task_queues.insert(task_queue.get(), QueueCheckResult::kDidNotSeeQueue);
  EXPECT_EQ(all_task_queues.size(), task_queue_created_count());

  task_queue = GetTaskQueue(
      QueueTraits().SetCanBePaused(true).SetCanRunWhenVirtualTimePaused(false));
  EXPECT_FALSE(all_task_queues.Contains(task_queue));
  all_task_queues.insert(task_queue.get(), QueueCheckResult::kDidNotSeeQueue);
  EXPECT_EQ(all_task_queues.size(), task_queue_created_count());

  task_queue =
      GetTaskQueue(QueueTraits().SetCanRunWhenVirtualTimePaused(false));
  EXPECT_FALSE(all_task_queues.Contains(task_queue));
  all_task_queues.insert(task_queue.get(), QueueCheckResult::kDidNotSeeQueue);
  EXPECT_EQ(all_task_queues.size(), task_queue_created_count());

  // Verify that we get all of the queues that we added, and only those queues.
  EXPECT_EQ(all_task_queues.size(),
            frame_task_queue_controller_->GetAllTaskQueuesAndVoters().size());
  for (const auto& task_queue_and_voter :
       frame_task_queue_controller_->GetAllTaskQueuesAndVoters()) {
    auto [task_queue_ptr, voter] = task_queue_and_voter;

    EXPECT_NE(task_queue_ptr, nullptr);
    EXPECT_TRUE(base::Contains(all_task_queues, task_queue_ptr));
    // Make sure we don't get the same queue twice.
    auto it = all_task_queues.find(task_queue_ptr);
    EXPECT_FALSE(it == all_task_queues.end());
    EXPECT_EQ(it->value, QueueCheckResult::kDidNotSeeQueue);
    all_task_queues.Set(task_queue_ptr, QueueCheckResult::kDidSeeQueue);
    EXPECT_NE(voter, nullptr);
  }
}

TEST_F(FrameTaskQueueControllerTest,
       NonWebSchedulingTaskQueueWebSchedulingPriorityNullopt) {
  scoped_refptr<MainThreadTaskQueue> task_queue =
      frame_task_queue_controller_->GetTaskQueue(
          MainThreadTaskQueue::QueueTraits());
  EXPECT_EQ(std::nullopt, task_queue->GetWebSchedulingPriority());
}

TEST_F(FrameTaskQueueControllerTest, AddWebSchedulingTaskQueues) {
  scoped_refptr<MainThreadTaskQueue> task_queue =
      frame_task_queue_controller_->NewWebSchedulingTaskQueue(
          QueueTraits(), WebSchedulingQueueType::kTaskQueue,
          WebSchedulingPriority::kUserBlockingPriority);
  EXPECT_EQ(1u,
            frame_task_queue_controller_->GetAllTaskQueuesAndVoters().size());
  EXPECT_EQ(WebSchedulingPriority::kUserBlockingPriority,
            task_queue->GetWebSchedulingPriority().value());

  task_queue = frame_task_queue_controller_->NewWebSchedulingTaskQueue(
      QueueTraits(), WebSchedulingQueueType::kTaskQueue,
      WebSchedulingPriority::kUserVisiblePriority);
  EXPECT_EQ(2u,
            frame_task_queue_controller_->GetAllTaskQueuesAndVoters().size());
  EXPECT_EQ(WebSchedulingPriority::kUserVisiblePriority,
            task_queue->GetWebSchedulingPriority().value());

  task_queue = frame_task_queue_controller_->NewWebSchedulingTaskQueue(
      QueueTraits(), WebSchedulingQueueType::kTaskQueue,
      WebSchedulingPriority::kBackgroundPriority);
  EXPECT_EQ(3u,
            frame_task_queue_controller_->GetAllTaskQueuesAndVoters().size());
  EXPECT_EQ(WebSchedulingPriority::kBackgroundPriority,
            task_queue->GetWebSchedulingPriority().value());
}

TEST_F(FrameTaskQueueControllerTest, RemoveWebSchedulingTaskQueues) {
  scoped_refptr<MainThreadTaskQueue> task_queue =
      frame_task_queue_controller_->NewWebSchedulingTaskQueue(
          QueueTraits(), WebSchedulingQueueType::kTaskQueue,
          WebSchedulingPriority::kUserBlockingPriority);
  EXPECT_EQ(1u,
            frame_task_queue_controller_->GetAllTaskQueuesAndVoters().size());
  EXPECT_EQ(WebSchedulingPriority::kUserBlockingPriority,
            task_queue->GetWebSchedulingPriority().value());

  scoped_refptr<MainThreadTaskQueue> task_queue2 =
      frame_task_queue_controller_->NewWebSchedulingTaskQueue(
          QueueTraits(), WebSchedulingQueueType::kTaskQueue,
          WebSchedulingPriority::kUserVisiblePriority);
  EXPECT_EQ(2u,
            frame_task_queue_controller_->GetAllTaskQueuesAndVoters().size());
  EXPECT_EQ(WebSchedulingPriority::kUserVisiblePriority,
            task_queue2->GetWebSchedulingPriority().value());

  frame_task_queue_controller_->RemoveWebSchedulingTaskQueue(task_queue.get());
  EXPECT_EQ(1u,
            frame_task_queue_controller_->GetAllTaskQueuesAndVoters().size());
  frame_task_queue_controller_->RemoveWebSchedulingTaskQueue(task_queue2.get());
  EXPECT_EQ(0u,
            frame_task_queue_controller_->GetAllTaskQueuesAndVoters().size());
}

TEST_F(FrameTaskQueueControllerTest,
       AddMultipleSamePriorityWebSchedulingTaskQueues) {
  scoped_refptr<MainThreadTaskQueue> task_queue1 =
      frame_task_queue_controller_->NewWebSchedulingTaskQueue(
          QueueTraits(), WebSchedulingQueueType::kTaskQueue,
          WebSchedulingPriority::kUserBlockingPriority);
  EXPECT_EQ(1u,
            frame_task_queue_controller_->GetAllTaskQueuesAndVoters().size());
  EXPECT_EQ(WebSchedulingPriority::kUserBlockingPriority,
            task_queue1->GetWebSchedulingPriority().value());

  scoped_refptr<MainThreadTaskQueue> task_queue2 =
      frame_task_queue_controller_->NewWebSchedulingTaskQueue(
          QueueTraits(), WebSchedulingQueueType::kTaskQueue,
          WebSchedulingPriority::kUserBlockingPriority);
  EXPECT_EQ(2u,
            frame_task_queue_controller_->GetAllTaskQueuesAndVoters().size());
  EXPECT_EQ(WebSchedulingPriority::kUserBlockingPriority,
            task_queue2->GetWebSchedulingPriority().value());

  EXPECT_NE(task_queue1.get(), task_queue2.get());
}

TEST_F(FrameTaskQueueControllerTest, QueueTypeFromQueueTraits) {
  scoped_refptr<MainThreadTaskQueue> task_queue = LoadingTaskQueue();
  EXPECT_EQ(task_queue->queue_type(),
            MainThreadTaskQueue::QueueType::kFrameLoading);

  task_queue = LoadingControlTaskQueue();
  EXPECT_EQ(task_queue->queue_type(),
            MainThreadTaskQueue::QueueType::kFrameLoadingControl);

  task_queue = ThrottleableTaskQueue();
  EXPECT_EQ(task_queue->queue_type(),
            MainThreadTaskQueue::QueueType::kFrameThrottleable);
}

class TaskQueueCreationFromQueueTraitsTest :
    public FrameTaskQueueControllerTest,
    public testing::WithParamInterface<QueueTraits::PrioritisationType> {};

INSTANTIATE_TEST_SUITE_P(
    All,
    TaskQueueCreationFromQueueTraitsTest,
    ::testing::Values(
        QueueTraits::PrioritisationType::kInternalScriptContinuation,
        QueueTraits::PrioritisationType::kBestEffort,
        QueueTraits::PrioritisationType::kRegular,
        QueueTraits::PrioritisationType::kLoading,
        QueueTraits::PrioritisationType::kLoadingControl,
        QueueTraits::PrioritisationType::kFindInPage,
        QueueTraits::PrioritisationType::kExperimentalDatabase,
        QueueTraits::PrioritisationType::kJavaScriptTimer,
        QueueTraits::PrioritisationType::kHighPriorityLocalFrame,
        QueueTraits::PrioritisationType::kInput));

TEST_P(TaskQueueCreationFromQueueTraitsTest,
        AddAndRetrieveAllTaskQueues) {
  // Create queues for all combination of queue traits for all combinations of
  // the 6 QueueTraits bits with different PrioritisationTypes.
  WTF::HashSet<scoped_refptr<MainThreadTaskQueue>> all_task_queues;
  constexpr size_t kTotalUniqueQueueTraits = 1 << 6;
  for (size_t i = 0; i < kTotalUniqueQueueTraits; i++) {
    QueueTraits::PrioritisationType prioritisation_type = GetParam();
    MainThreadTaskQueue::QueueTraits queue_traits =
        QueueTraits()
            .SetCanBeThrottled(!!(i & 1 << 0))
            .SetCanBeDeferred(!!(i & 1 << 1))
            .SetCanBeFrozen(!!(i & 1 << 2))
            .SetCanBePaused(!!(i & 1 << 3))
            .SetCanRunInBackground(!!(i & 1 << 4))
            .SetCanRunWhenVirtualTimePaused(!!(i & 1 << 5))
            .SetPrioritisationType(prioritisation_type);
    scoped_refptr<MainThreadTaskQueue> task_queue =
        frame_task_queue_controller_->GetTaskQueue(queue_traits);
    EXPECT_FALSE(all_task_queues.Contains(task_queue));
    all_task_queues.insert(task_queue);
    EXPECT_EQ(task_queue->GetQueueTraits(), queue_traits);
    EXPECT_EQ(task_queue->GetQueueTraits().prioritisation_type,
              prioritisation_type);
  }
  // Make sure we get the same queues back, with matching QueueTraits.
  EXPECT_EQ(all_task_queues.size(), kTotalUniqueQueueTraits);
  for (const auto& task_queue : all_task_queues) {
    scoped_refptr<MainThreadTaskQueue> returned_task_queue =
        frame_task_queue_controller_->GetTaskQueue(
            task_queue->GetQueueTraits());
    EXPECT_EQ(task_queue->GetQueueTraits(),
              returned_task_queue->GetQueueTraits());
    EXPECT_TRUE(task_queue == returned_task_queue);
  }
}

}  // namespace scheduler
}  // namespace blink

"""

```