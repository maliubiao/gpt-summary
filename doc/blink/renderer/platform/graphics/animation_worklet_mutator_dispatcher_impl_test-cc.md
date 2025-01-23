Response:
Let's break down the thought process for analyzing the provided C++ test file.

**1. Initial Understanding - What is this file about?**

* The file path `blink/renderer/platform/graphics/animation_worklet_mutator_dispatcher_impl_test.cc` immediately tells us this is a test file for something related to `animation_worklet_mutator_dispatcher_impl`.
* The `#include` directives confirm this and also hint at dependencies like `AnimationWorkletMutator`, `CompositorMutatorClient`, and various testing frameworks (`gmock`, `gtest`).
* The copyright notice at the top confirms it's part of the Chromium project.

**2. Deconstructing the Code - Identifying Key Components:**

* **Includes:** Carefully examine the included headers. They reveal the core components being tested and the testing infrastructure being used. Key inclusions are:
    * `AnimationWorkletMutatorDispatcherImpl.h`:  The class being tested.
    * `AnimationWorkletMutator.h`:  An interface the dispatcher interacts with.
    * `CompositorMutatorClient.h`: Another interface the dispatcher interacts with.
    * `testing/gmock/include/gmock/gmock.h` and `testing/gtest/include/gtest/gtest.h`:  Indicate this is a unit test using Google Mock and Google Test.
    * `platform/scheduler/...`:  Suggests involvement with threading and asynchronous operations.

* **Helper Functions/Classes:** Look for local definitions within the `blink::` namespace:
    * `CreateThread`:  Clearly a helper to create test threads.
    * `MockAnimationWorkletMutator`:  A mock implementation of `AnimationWorkletMutator`. This is crucial for isolating the dispatcher's behavior. The `MOCK_METHOD` macros indicate how interactions with this mock will be verified.
    * `MockCompositorMutatorClient`: A mock implementation of `CompositorMutatorClient`. Similar purpose to the previous mock.
    * `AnimationWorkletMutatorDispatcherImplTest`: The base test fixture class. It sets up the dispatcher and mock client.
    * `CreateTestMutatorInput`:  A utility function to create test input for the dispatcher.

* **Test Cases (TEST_F):** The core of the file. Each `TEST_F` defines a specific scenario to test the `AnimationWorkletMutatorDispatcherImpl`. Pay attention to the names of the test cases, as they usually describe what's being tested. Examples:
    * `RegisteredAnimatorShouldOnlyReceiveInputForItself`
    * `MutationUpdateIsNotInvokedWithNoRegisteredAnimators`
    * `MutationUpdateQueuedWhenBusy`
    * `HistogramTester`

* **Mock Expectations (EXPECT_CALL):**  These are the core of the Google Mock framework. They define how the mocks are *expected* to be called during the test. Analyzing these calls reveals the intended behavior being verified.

* **Assertions (EXPECT_TRUE, EXPECT_FALSE, EXPECT_EQ):** Standard Google Test assertions to check the outcome of the operations.

* **Asynchronous Testing (`AnimationWorkletMutatorDispatcherImplAsyncTest`):**  A separate test fixture for testing asynchronous scenarios. The use of `base::RunLoop` and completion callbacks (`CreateTestCompleteCallback`) indicates asynchronous behavior.

**3. Analyzing Functionality and Connections:**

* **Core Function:** The `AnimationWorkletMutatorDispatcherImpl` is responsible for managing and dispatching mutations to `AnimationWorkletMutator` instances. It likely acts as an intermediary between some higher-level animation system and the worklets.
* **Interaction with JavaScript/HTML/CSS:**
    * **Animation Worklets:**  The name itself points to the Animation Worklet API in JavaScript. This API allows developers to write custom animation logic.
    * **Mutations:** The concept of "mutations" suggests changes being applied to the visual state of the web page, which is directly related to how CSS properties are animated.
    * **Compositor:** The interaction with `CompositorMutatorClient` strongly suggests involvement with the browser's compositor thread, which is responsible for efficiently rendering the page. This implies the dispatcher helps apply the effects of Animation Worklets to the rendering process.

**4. Logic and Assumptions:**

* **Input/Output:** Consider the `CreateTestMutatorInput` function. It creates a specific input structure. The tests then verify how the dispatcher processes this input and what output (via `SetMutationUpdateRef` on the mock client) is produced.
* **Threading:** The use of multiple threads and `PostCrossThreadTask` is significant. The dispatcher needs to handle communication and synchronization between different threads. The asynchronous tests specifically target these scenarios.
* **Queuing Strategies:** The `MutateQueuingStrategy` enum and tests like `MutationUpdateDroppedWhenBusy` and `MutationUpdateQueuedWhenBusy` highlight how the dispatcher handles multiple mutation requests when the worklet is busy.

**5. Common Errors:**

* **Incorrect Registration/Unregistration:**  Tests verify that registering and unregistering worklets work correctly and that unregistered worklets aren't invoked.
* **Race Conditions (in asynchronous tests):** The `BlockWorkletThread` and `UnblockWorkletThread` methods in `MockAnimationWorkletMutator` are specifically designed to prevent race conditions during asynchronous testing by controlling the timing of worklet execution.
* **Null Output Handling:**  A test verifies the dispatcher's behavior when a worklet returns a null output.

**Self-Correction/Refinement during the Process:**

* **Initial Guess vs. Detailed Analysis:**  An initial quick glance might just say "tests the animation worklet dispatcher." But the detailed analysis of includes, mocks, and test cases reveals much more specific functionality being tested.
* **Connecting the Dots:**  Realizing the connection between Animation Worklets, mutations, and the compositor is a key insight. It explains why these specific interfaces are involved.
* **Understanding the Test Structure:** Recognizing the different test fixtures for synchronous and asynchronous scenarios helps understand the testing approach.

By following this structured approach, one can systematically analyze the C++ test file and extract its core functionalities, connections to web technologies, and potential error scenarios.
这个C++文件 `animation_worklet_mutator_dispatcher_impl_test.cc` 是 Chromium Blink 引擎的一部分，其主要功能是 **测试 `AnimationWorkletMutatorDispatcherImpl` 类的实现**。

`AnimationWorkletMutatorDispatcherImpl`  在 Blink 引擎中扮演着一个重要的角色，它负责管理和调度 Animation Worklet Mutator。Animation Worklet 是一个允许开发者使用 JavaScript 定义自定义动画效果的特性。Mutator 是 Worklet 的一部分，它允许修改元素的渲染属性，从而实现高级的动画效果。

以下是这个测试文件更详细的功能分解以及与 JavaScript、HTML、CSS 的关系：

**1. 功能概述:**

* **测试 `AnimationWorkletMutatorDispatcherImpl` 的核心逻辑:**  测试它如何注册、取消注册 Animation Worklet Mutator，以及如何将需要执行的 mutation（修改）分发到正确的 Mutator 上。
* **验证同步和异步的 mutation 分发:** 测试同步 (`MutateSynchronously`) 和异步 (`MutateAsynchronously`) 两种模式下的 mutation 处理流程。
* **模拟 Animation Worklet Mutator 的行为:** 使用 `MockAnimationWorkletMutator` 类来模拟真实的 Animation Worklet Mutator 的行为，例如接收输入、执行 mutation 并返回输出。
* **模拟 CompositorMutatorClient 的行为:** 使用 `MockCompositorMutatorClient` 类来模拟 Compositor 的客户端，验证 `AnimationWorkletMutatorDispatcherImpl` 是否正确地将 mutation 结果传递给 Compositor。
* **测试不同线程环境下的行为:**  测试在单线程和多线程环境下，mutation 分发是否正确。
* **测试在 Mutator 繁忙时的队列管理策略:** 测试当 Mutator 正在处理 mutation 时，新的 mutation 请求如何被处理（例如，排队、丢弃、替换）。
* **测试性能指标的收集:**  使用 `HistogramTester` 测试异步 mutation 的执行时长是否被正确记录。
* **覆盖各种边界情况和错误处理:**  例如，当没有注册的 Mutator、Mutator 返回空输出等情况。

**2. 与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript (Animation Worklet API):**  这个测试文件直接关系到 JavaScript 的 Animation Worklet API。开发者可以使用 JavaScript 代码注册一个 Animation Worklet，并在其中定义 Mutator 函数。`AnimationWorkletMutatorDispatcherImpl` 负责协调这些 JavaScript 定义的 Mutator 的执行。
    * **例子:**  在 JavaScript 中，你可能会写出类似这样的代码：
      ```javascript
      registerAnimator('custom-animator', class {
        constructor(options) {
          this.options = options;
        }
        animate(currentTime, timeline) {
          // 基于 currentTime 和 timeline 计算一些值
          const scale = 1 + Math.sin(currentTime / 1000);
          return [
            { target: this.options.targetElement, scale: scale }
          ];
        }
      });
      ```
      当这个 Worklet 被应用到一个 HTML 元素上时，`AnimationWorkletMutatorDispatcherImpl` 负责将相关的动画输入数据传递给在独立线程中运行的 Worklet 的 `animate` 方法。

* **HTML (元素和动画目标):**  HTML 元素是 Animation Worklet 动画的目标。在 JavaScript 的 Animation Worklet 代码中，你可以指定哪些 HTML 元素需要被修改。
    * **例子:**  在上面的 JavaScript 例子中，`this.options.targetElement` 可能对应着一个特定的 HTML 元素，例如 `<div id="animated-box"></div>`。`AnimationWorkletMutatorDispatcherImpl` 接收到 Worklet 的输出后，会指示 Compositor 对这个 HTML 元素进行相应的渲染更新。

* **CSS (渲染属性修改):** Animation Worklet Mutator 的最终目的是修改元素的渲染属性，这与 CSS 的工作方式密切相关。Worklet 的 `animate` 方法返回的输出通常会映射到一些 CSS 属性的修改。
    * **例子:**  在上面的 JavaScript 例子中，`scale: scale`  可能最终会影响 HTML 元素的 `transform: scale(...)` CSS 属性。`AnimationWorkletMutatorDispatcherImpl` 确保这些修改能够高效地应用到渲染管道中。

**3. 逻辑推理及假设输入与输出:**

让我们以其中一个测试用例为例进行逻辑推理：

**测试用例:** `RegisteredAnimatorShouldOnlyReceiveInputForItself`

**假设输入:**

* 注册了一个 `MockAnimationWorkletMutator`，其 `GetWorkletId` 返回 `11`。
* 创建了一个 `AnimationWorkletDispatcherInput`，其中包含两个动画状态：
    * `animation_id: 1`, `worklet_id: 11`
    * `animation_id: 2`, `worklet_id: 22`

**逻辑推理:**

1. `AnimationWorkletMutatorDispatcherImpl` 接收到 `MutateSynchronously` 请求，并传入上述的 `AnimationWorkletDispatcherInput`。
2. Dispatcher 会遍历输入中的动画状态，并根据 `worklet_id` 找到对应的已注册的 Mutator。
3. 由于注册的 Mutator 的 `worklet_id` 是 `11`，因此只有 `animation_id` 为 `1` 的动画状态会被传递给这个 Mutator。
4. `MockAnimationWorkletMutator` 的 `MutateRef` 方法应该只被调用一次，且接收到的 `AnimationWorkletInput` 中只包含 `animation_id` 为 `1` 的动画状态。
5. Mutator 返回一个新的 `AnimationWorkletOutput`。
6. Dispatcher 将 Mutator 的输出传递给 `MockCompositorMutatorClient` 的 `SetMutationUpdateRef` 方法。

**预期输出:**

* `MockAnimationWorkletMutator::MutateRef` 被调用一次，且传入的 `AnimationWorkletInput` 满足 `OnlyIncludesAnimation1` 断言（即只包含 `animation_id` 为 `1` 的动画）。
* `MockCompositorMutatorClient::SetMutationUpdateRef` 被调用一次。

**4. 用户或编程常见的使用错误举例:**

* **忘记注册 Animation Worklet:** 如果开发者在 JavaScript 中定义了 Animation Worklet，但忘记使用 `registerAnimator` 进行注册，那么 `AnimationWorkletMutatorDispatcherImpl` 将无法找到对应的 Mutator，动画将不会生效。
* **Worklet ID 不匹配:**  如果在 JavaScript 中定义的 Worklet ID 与在其他地方引用的 ID 不一致，`AnimationWorkletMutatorDispatcherImpl` 将无法正确地将 mutation 分发到对应的 Worklet。
* **在 Mutator 中执行耗时操作:**  Animation Worklet Mutator 运行在独立的线程中，但如果 Mutator 的 `animate` 函数执行了过于耗时的操作，可能会导致动画卡顿或性能问题。`AnimationWorkletMutatorDispatcherImpl` 的队列管理策略可以缓解这种情况，但根本上还是需要优化 Mutator 的代码。
* **异步 mutation 的错误处理:**  在使用异步 mutation 时，如果开发者没有正确处理完成回调或错误回调，可能会导致资源泄漏或其他未预期的行为。测试文件中的异步测试用例就涵盖了对不同完成状态的处理。
* **并发访问共享状态:**  如果多个 Animation Worklet Mutator 试图并发地修改相同的渲染属性，可能会导致竞争条件和不可预测的结果。开发者需要仔细设计 Mutator 的逻辑以避免这种情况。

总而言之，`animation_worklet_mutator_dispatcher_impl_test.cc`  是一个关键的测试文件，它确保了 Blink 引擎中 Animation Worklet Mutator 分发机制的正确性和稳定性，从而保证了使用 Animation Worklet API 开发的动画能够按照预期工作。

### 提示词
```
这是目录为blink/renderer/platform/graphics/animation_worklet_mutator_dispatcher_impl_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/animation_worklet_mutator_dispatcher_impl.h"

#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/simple_test_tick_clock.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/platform/graphics/animation_worklet_mutator.h"
#include "third_party/blink/renderer/platform/graphics/compositor_mutator_client.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/scheduler/public/non_main_thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_type.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"

#include <memory>

using ::testing::_;
using ::testing::AtLeast;
using ::testing::Mock;
using ::testing::Return;
using ::testing::Sequence;
using ::testing::StrictMock;
using ::testing::Truly;

// This test uses actual threads since mutator logic requires it. This means we
// have dependency on Blink platform to create threads.

namespace blink {
namespace {

std::unique_ptr<NonMainThread> CreateThread(const char* name) {
  return NonMainThread::CreateThread(
      ThreadCreationParams(ThreadType::kTestThread).SetThreadNameForTest(name));
}

class MockAnimationWorkletMutator
    : public GarbageCollected<MockAnimationWorkletMutator>,
      public AnimationWorkletMutator {
 public:
  MockAnimationWorkletMutator(
      scoped_refptr<base::SingleThreadTaskRunner> expected_runner)
      : expected_runner_(expected_runner) {}

  ~MockAnimationWorkletMutator() override {}

  std::unique_ptr<AnimationWorkletOutput> Mutate(
      std::unique_ptr<AnimationWorkletInput> input) override {
    return std::unique_ptr<AnimationWorkletOutput>(MutateRef(*input));
  }

  // Blocks the worklet thread by posting a task that will complete only when
  // signaled. This blocking ensures that tests of async mutations do not
  // encounter race conditions when validating queuing strategies.
  void BlockWorkletThread() {
    PostCrossThreadTask(
        *expected_runner_, FROM_HERE,
        CrossThreadBindOnce(
            [](base::WaitableEvent* start_processing_event) {
              start_processing_event->Wait();
            },
            WTF::CrossThreadUnretained(&start_processing_event_)));
  }

  void UnblockWorkletThread() { start_processing_event_.Signal(); }

  MOCK_CONST_METHOD0(GetWorkletId, int());
  MOCK_METHOD1(MutateRef,
               AnimationWorkletOutput*(const AnimationWorkletInput&));

  scoped_refptr<base::SingleThreadTaskRunner> expected_runner_;
  base::WaitableEvent start_processing_event_;
};

class MockCompositorMutatorClient : public CompositorMutatorClient {
 public:
  MockCompositorMutatorClient(
      std::unique_ptr<AnimationWorkletMutatorDispatcherImpl> mutator)
      : CompositorMutatorClient(std::move(mutator)) {}
  ~MockCompositorMutatorClient() override {}
  // gmock cannot mock methods with move-only args so we forward it to ourself.
  void SetMutationUpdate(
      std::unique_ptr<cc::MutatorOutputState> output_state) override {
    SetMutationUpdateRef(output_state.get());
  }

  MOCK_METHOD1(SetMutationUpdateRef,
               void(cc::MutatorOutputState* output_state));
};

class AnimationWorkletMutatorDispatcherImplTest : public ::testing::Test {
 public:
  void SetUp() override {
    auto mutator = std::make_unique<AnimationWorkletMutatorDispatcherImpl>(
        scheduler::GetSingleThreadTaskRunnerForTesting());
    mutator_ = mutator.get();
    client_ =
        std::make_unique<::testing::StrictMock<MockCompositorMutatorClient>>(
            std::move(mutator));
  }

  void TearDown() override { mutator_ = nullptr; }

  test::TaskEnvironment task_environment_;
  std::unique_ptr<::testing::StrictMock<MockCompositorMutatorClient>> client_;
  raw_ptr<AnimationWorkletMutatorDispatcherImpl> mutator_;
};

std::unique_ptr<AnimationWorkletDispatcherInput> CreateTestMutatorInput() {
  AnimationWorkletInput::AddAndUpdateState state1{
      {11, 1}, "test1", 5000, nullptr, nullptr};

  AnimationWorkletInput::AddAndUpdateState state2{
      {22, 2}, "test2", 5000, nullptr, nullptr};

  auto input = std::make_unique<AnimationWorkletDispatcherInput>();
  input->Add(std::move(state1));
  input->Add(std::move(state2));

  return input;
}

bool OnlyIncludesAnimation1(const AnimationWorkletInput& in) {
  return in.added_and_updated_animations.size() == 1 &&
         in.added_and_updated_animations[0].worklet_animation_id.animation_id ==
             1;
}

TEST_F(AnimationWorkletMutatorDispatcherImplTest,
       RegisteredAnimatorShouldOnlyReceiveInputForItself) {
  std::unique_ptr<NonMainThread> first_thread = CreateThread("FirstThread");
  MockAnimationWorkletMutator* first_mutator =
      MakeGarbageCollected<MockAnimationWorkletMutator>(
          first_thread->GetTaskRunner());

  mutator_->RegisterAnimationWorkletMutator(
      WrapCrossThreadPersistent(first_mutator), first_thread->GetTaskRunner());

  EXPECT_CALL(*first_mutator, GetWorkletId())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(11));
  EXPECT_CALL(*first_mutator, MutateRef(Truly(OnlyIncludesAnimation1)))
      .Times(1)
      .WillOnce(Return(new AnimationWorkletOutput()));
  EXPECT_CALL(*client_, SetMutationUpdateRef(_)).Times(1);
  mutator_->MutateSynchronously(CreateTestMutatorInput());
}

TEST_F(AnimationWorkletMutatorDispatcherImplTest,
       RegisteredAnimatorShouldNotBeMutatedWhenNoInput) {
  std::unique_ptr<NonMainThread> first_thread = CreateThread("FirstThread");
  MockAnimationWorkletMutator* first_mutator =
      MakeGarbageCollected<MockAnimationWorkletMutator>(
          first_thread->GetTaskRunner());

  mutator_->RegisterAnimationWorkletMutator(
      WrapCrossThreadPersistent(first_mutator), first_thread->GetTaskRunner());

  EXPECT_CALL(*first_mutator, GetWorkletId())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(11));
  EXPECT_CALL(*first_mutator, MutateRef(_)).Times(0);
  EXPECT_CALL(*client_, SetMutationUpdateRef(_)).Times(0);

  AnimationWorkletInput::AddAndUpdateState state{
      {22, 2}, "test2", 5000, nullptr, nullptr};

  auto input = std::make_unique<AnimationWorkletDispatcherInput>();
  input->Add(std::move(state));

  mutator_->MutateSynchronously(std::move(input));
}

TEST_F(AnimationWorkletMutatorDispatcherImplTest,
       MutationUpdateIsNotInvokedWithNoRegisteredAnimators) {
  EXPECT_CALL(*client_, SetMutationUpdateRef(_)).Times(0);
  std::unique_ptr<AnimationWorkletDispatcherInput> input =
      std::make_unique<AnimationWorkletDispatcherInput>();
  mutator_->MutateSynchronously(std::move(input));
}

TEST_F(AnimationWorkletMutatorDispatcherImplTest,
       MutationUpdateIsNotInvokedWithNullOutput) {
  // Create a thread to run mutator tasks.
  std::unique_ptr<NonMainThread> first_thread =
      CreateThread("FirstAnimationThread");
  MockAnimationWorkletMutator* first_mutator =
      MakeGarbageCollected<MockAnimationWorkletMutator>(
          first_thread->GetTaskRunner());

  mutator_->RegisterAnimationWorkletMutator(
      WrapCrossThreadPersistent(first_mutator), first_thread->GetTaskRunner());

  EXPECT_CALL(*first_mutator, GetWorkletId())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(11));
  EXPECT_CALL(*first_mutator, MutateRef(_)).Times(1).WillOnce(Return(nullptr));
  EXPECT_CALL(*client_, SetMutationUpdateRef(_)).Times(0);
  mutator_->MutateSynchronously(CreateTestMutatorInput());
}

TEST_F(AnimationWorkletMutatorDispatcherImplTest,
       MutationUpdateIsInvokedCorrectlyWithSingleRegisteredAnimator) {
  // Create a thread to run mutator tasks.
  std::unique_ptr<NonMainThread> first_thread =
      CreateThread("FirstAnimationThread");
  MockAnimationWorkletMutator* first_mutator =
      MakeGarbageCollected<MockAnimationWorkletMutator>(
          first_thread->GetTaskRunner());

  mutator_->RegisterAnimationWorkletMutator(
      WrapCrossThreadPersistent(first_mutator), first_thread->GetTaskRunner());

  EXPECT_CALL(*first_mutator, GetWorkletId())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(11));
  EXPECT_CALL(*first_mutator, MutateRef(_))
      .Times(1)
      .WillOnce(Return(new AnimationWorkletOutput()));
  EXPECT_CALL(*client_, SetMutationUpdateRef(_)).Times(1);
  mutator_->MutateSynchronously(CreateTestMutatorInput());

  // The above call blocks on mutator threads running their tasks so we can
  // safely verify here.
  Mock::VerifyAndClearExpectations(client_.get());

  // Ensure mutator is not invoked after unregistration.
  EXPECT_CALL(*first_mutator, MutateRef(_)).Times(0);
  EXPECT_CALL(*client_, SetMutationUpdateRef(_)).Times(0);
  mutator_->UnregisterAnimationWorkletMutator(
      WrapCrossThreadPersistent(first_mutator));

  mutator_->MutateSynchronously(CreateTestMutatorInput());
  Mock::VerifyAndClearExpectations(client_.get());
}

TEST_F(AnimationWorkletMutatorDispatcherImplTest,
       MutationUpdateInvokedCorrectlyWithTwoRegisteredAnimatorsOnSameThread) {
  std::unique_ptr<NonMainThread> first_thread =
      CreateThread("FirstAnimationThread");
  MockAnimationWorkletMutator* first_mutator =
      MakeGarbageCollected<MockAnimationWorkletMutator>(
          first_thread->GetTaskRunner());
  MockAnimationWorkletMutator* second_mutator =
      MakeGarbageCollected<MockAnimationWorkletMutator>(
          first_thread->GetTaskRunner());

  mutator_->RegisterAnimationWorkletMutator(
      WrapCrossThreadPersistent(first_mutator), first_thread->GetTaskRunner());
  mutator_->RegisterAnimationWorkletMutator(
      WrapCrossThreadPersistent(second_mutator), first_thread->GetTaskRunner());

  EXPECT_CALL(*first_mutator, GetWorkletId())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(11));
  EXPECT_CALL(*first_mutator, MutateRef(_))
      .Times(1)
      .WillOnce(Return(new AnimationWorkletOutput()));
  EXPECT_CALL(*second_mutator, GetWorkletId())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(22));
  EXPECT_CALL(*second_mutator, MutateRef(_))
      .Times(1)
      .WillOnce(Return(new AnimationWorkletOutput()));
  EXPECT_CALL(*client_, SetMutationUpdateRef(_)).Times(2);
  mutator_->MutateSynchronously(CreateTestMutatorInput());
}

TEST_F(
    AnimationWorkletMutatorDispatcherImplTest,
    MutationUpdateInvokedCorrectlyWithTwoRegisteredAnimatorsOnDifferentThreads) {
  std::unique_ptr<NonMainThread> first_thread =
      CreateThread("FirstAnimationThread");
  MockAnimationWorkletMutator* first_mutator =
      MakeGarbageCollected<MockAnimationWorkletMutator>(
          first_thread->GetTaskRunner());

  std::unique_ptr<NonMainThread> second_thread =
      CreateThread("SecondAnimationThread");
  MockAnimationWorkletMutator* second_mutator =
      MakeGarbageCollected<MockAnimationWorkletMutator>(
          second_thread->GetTaskRunner());

  mutator_->RegisterAnimationWorkletMutator(
      WrapCrossThreadPersistent(first_mutator), first_thread->GetTaskRunner());
  mutator_->RegisterAnimationWorkletMutator(
      WrapCrossThreadPersistent(second_mutator),
      second_thread->GetTaskRunner());

  EXPECT_CALL(*first_mutator, GetWorkletId())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(11));
  EXPECT_CALL(*first_mutator, MutateRef(_))
      .Times(1)
      .WillOnce(Return(new AnimationWorkletOutput()));
  EXPECT_CALL(*second_mutator, GetWorkletId())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(22));
  EXPECT_CALL(*second_mutator, MutateRef(_))
      .Times(1)
      .WillOnce(Return(new AnimationWorkletOutput()));
  EXPECT_CALL(*client_, SetMutationUpdateRef(_)).Times(2);
  mutator_->MutateSynchronously(CreateTestMutatorInput());

  // The above call blocks on mutator threads running their tasks so we can
  // safely verify here.
  Mock::VerifyAndClearExpectations(client_.get());

  // Ensure first_mutator is not invoked after unregistration.
  mutator_->UnregisterAnimationWorkletMutator(
      WrapCrossThreadPersistent(first_mutator));

  EXPECT_CALL(*first_mutator, GetWorkletId()).Times(0);
  EXPECT_CALL(*first_mutator, MutateRef(_)).Times(0);
  EXPECT_CALL(*second_mutator, GetWorkletId())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(22));
  EXPECT_CALL(*second_mutator, MutateRef(_))
      .Times(1)
      .WillOnce(Return(new AnimationWorkletOutput()));
  EXPECT_CALL(*client_, SetMutationUpdateRef(_)).Times(1);
  mutator_->MutateSynchronously(CreateTestMutatorInput());

  Mock::VerifyAndClearExpectations(client_.get());
}

TEST_F(AnimationWorkletMutatorDispatcherImplTest,
       DispatcherShouldNotHangWhenMutatorGoesAway) {
  // Create a thread to run mutator tasks.
  std::unique_ptr<NonMainThread> first_thread =
      CreateThread("FirstAnimationThread");
  MockAnimationWorkletMutator* first_mutator =
      MakeGarbageCollected<MockAnimationWorkletMutator>(
          first_thread->GetTaskRunner());

  mutator_->RegisterAnimationWorkletMutator(
      WrapCrossThreadPersistent(first_mutator), first_thread->GetTaskRunner());

  EXPECT_CALL(*first_mutator, GetWorkletId()).WillRepeatedly(Return(11));
  EXPECT_CALL(*client_, SetMutationUpdateRef(_)).Times(0);

  // Shutdown the thread so its task runner no longer executes tasks.
  first_thread.reset();

  mutator_->MutateSynchronously(CreateTestMutatorInput());

  Mock::VerifyAndClearExpectations(client_.get());
}

// -----------------------------------------------------------------------
// Asynchronous version of tests.

using MutatorDispatcherRef =
    scoped_refptr<AnimationWorkletMutatorDispatcherImpl>;

class AnimationWorkletMutatorDispatcherImplAsyncTest
    : public AnimationWorkletMutatorDispatcherImplTest {
 public:
  AnimationWorkletMutatorDispatcher::AsyncMutationCompleteCallback
  CreateIntermediateResultCallback(MutateStatus expected_result) {
    return CrossThreadBindOnce(
        &AnimationWorkletMutatorDispatcherImplAsyncTest ::
            VerifyExpectedMutationResult,
        CrossThreadUnretained(this), expected_result);
  }

  AnimationWorkletMutatorDispatcher::AsyncMutationCompleteCallback
  CreateNotReachedCallback() {
    return CrossThreadBindOnce([](MutateStatus unused) {
      NOTREACHED() << "Mutate complete callback should not have been triggered";
    });
  }

  AnimationWorkletMutatorDispatcher::AsyncMutationCompleteCallback
  CreateTestCompleteCallback(
      MutateStatus expected_result = MutateStatus::kCompletedWithUpdate) {
    return CrossThreadBindOnce(
        &AnimationWorkletMutatorDispatcherImplAsyncTest ::
            VerifyCompletedMutationResultAndFinish,
        CrossThreadUnretained(this), expected_result);
  }

  // Executes run loop until quit closure is called.
  void WaitForTestCompletion() { run_loop_.Run(); }

  void VerifyExpectedMutationResult(MutateStatus expectation,
                                    MutateStatus result) {
    EXPECT_EQ(expectation, result);
    IntermediateResultCallbackRef();
  }

  void VerifyCompletedMutationResultAndFinish(MutateStatus expectation,
                                              MutateStatus result) {
    EXPECT_EQ(expectation, result);
    run_loop_.Quit();
  }

  // Verifying that intermediate result callbacks are invoked the correct number
  // of times.
  MOCK_METHOD0(IntermediateResultCallbackRef, void());

  static const MutateQueuingStrategy kNormalPriority =
      MutateQueuingStrategy::kQueueAndReplaceNormalPriority;

  static const MutateQueuingStrategy kHighPriority =
      MutateQueuingStrategy::kQueueHighPriority;

 private:
  base::RunLoop run_loop_;
};

TEST_F(AnimationWorkletMutatorDispatcherImplAsyncTest,
       RegisteredAnimatorShouldOnlyReceiveInputForItself) {
  std::unique_ptr<NonMainThread> first_thread = CreateThread("FirstThread");
  MockAnimationWorkletMutator* first_mutator =
      MakeGarbageCollected<MockAnimationWorkletMutator>(
          first_thread->GetTaskRunner());

  mutator_->RegisterAnimationWorkletMutator(
      WrapCrossThreadPersistent(first_mutator), first_thread->GetTaskRunner());

  EXPECT_CALL(*first_mutator, GetWorkletId())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(11));
  EXPECT_CALL(*first_mutator, MutateRef(_))
      .Times(1)
      .WillOnce(Return(new AnimationWorkletOutput()));
  EXPECT_CALL(*client_, SetMutationUpdateRef(_)).Times(1);

  EXPECT_TRUE(mutator_->MutateAsynchronously(
      CreateTestMutatorInput(), kNormalPriority, CreateTestCompleteCallback()));

  WaitForTestCompletion();
}

TEST_F(AnimationWorkletMutatorDispatcherImplAsyncTest,
       RegisteredAnimatorShouldNotBeMutatedWhenNoInput) {
  std::unique_ptr<NonMainThread> first_thread = CreateThread("FirstThread");
  MockAnimationWorkletMutator* first_mutator =
      MakeGarbageCollected<MockAnimationWorkletMutator>(
          first_thread->GetTaskRunner());

  mutator_->RegisterAnimationWorkletMutator(
      WrapCrossThreadPersistent(first_mutator), first_thread->GetTaskRunner());

  AnimationWorkletInput::AddAndUpdateState state{
      {22, 2}, "test2", 5000, nullptr, nullptr};

  auto input = std::make_unique<AnimationWorkletDispatcherInput>();
  input->Add(std::move(state));

  EXPECT_CALL(*first_mutator, GetWorkletId())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(11));

  EXPECT_FALSE(mutator_->MutateAsynchronously(std::move(input), kNormalPriority,
                                              CreateNotReachedCallback()));
}

TEST_F(AnimationWorkletMutatorDispatcherImplAsyncTest,
       MutationUpdateIsNotInvokedWithNoRegisteredAnimators) {
  EXPECT_CALL(*client_, SetMutationUpdateRef(_)).Times(0);
  std::unique_ptr<AnimationWorkletDispatcherInput> input =
      std::make_unique<AnimationWorkletDispatcherInput>();
  EXPECT_FALSE(mutator_->MutateAsynchronously(std::move(input), kNormalPriority,
                                              CreateNotReachedCallback()));
}

TEST_F(AnimationWorkletMutatorDispatcherImplAsyncTest,
       MutationUpdateIsNotInvokedWithNullOutput) {
  // Create a thread to run mutator tasks.
  std::unique_ptr<NonMainThread> first_thread =
      CreateThread("FirstAnimationThread");
  MockAnimationWorkletMutator* first_mutator =
      MakeGarbageCollected<MockAnimationWorkletMutator>(
          first_thread->GetTaskRunner());

  mutator_->RegisterAnimationWorkletMutator(
      WrapCrossThreadPersistent(first_mutator), first_thread->GetTaskRunner());

  EXPECT_CALL(*first_mutator, GetWorkletId())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(11));
  EXPECT_CALL(*first_mutator, MutateRef(_)).Times(1).WillOnce(Return(nullptr));
  EXPECT_CALL(*client_, SetMutationUpdateRef(_)).Times(0);

  EXPECT_TRUE(mutator_->MutateAsynchronously(
      CreateTestMutatorInput(), kNormalPriority,
      CreateTestCompleteCallback(MutateStatus::kCompletedNoUpdate)));

  WaitForTestCompletion();
}

TEST_F(AnimationWorkletMutatorDispatcherImplAsyncTest,
       MutationUpdateIsInvokedCorrectlyWithSingleRegisteredAnimator) {
  // Create a thread to run mutator tasks.
  std::unique_ptr<NonMainThread> first_thread =
      CreateThread("FirstAnimationThread");
  MockAnimationWorkletMutator* first_mutator =
      MakeGarbageCollected<MockAnimationWorkletMutator>(
          first_thread->GetTaskRunner());

  mutator_->RegisterAnimationWorkletMutator(
      WrapCrossThreadPersistent(first_mutator), first_thread->GetTaskRunner());

  EXPECT_CALL(*first_mutator, GetWorkletId())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(11));
  EXPECT_CALL(*first_mutator, MutateRef(_))
      .Times(1)
      .WillOnce(Return(new AnimationWorkletOutput()));
  EXPECT_CALL(*client_, SetMutationUpdateRef(_)).Times(1);

  EXPECT_TRUE(mutator_->MutateAsynchronously(
      CreateTestMutatorInput(), kNormalPriority, CreateTestCompleteCallback()));

  WaitForTestCompletion();

  // Above call blocks until complete signal is received.
  Mock::VerifyAndClearExpectations(client_.get());

  // Ensure mutator is not invoked after unregistration.
  mutator_->UnregisterAnimationWorkletMutator(
      WrapCrossThreadPersistent(first_mutator));
  EXPECT_FALSE(mutator_->MutateAsynchronously(
      CreateTestMutatorInput(), kNormalPriority, CreateNotReachedCallback()));

  Mock::VerifyAndClearExpectations(client_.get());
}

TEST_F(AnimationWorkletMutatorDispatcherImplAsyncTest,
       MutationUpdateInvokedCorrectlyWithTwoRegisteredAnimatorsOnSameThread) {
  std::unique_ptr<NonMainThread> first_thread =
      CreateThread("FirstAnimationThread");
  MockAnimationWorkletMutator* first_mutator =
      MakeGarbageCollected<MockAnimationWorkletMutator>(
          first_thread->GetTaskRunner());
  MockAnimationWorkletMutator* second_mutator =
      MakeGarbageCollected<MockAnimationWorkletMutator>(
          first_thread->GetTaskRunner());

  mutator_->RegisterAnimationWorkletMutator(
      WrapCrossThreadPersistent(first_mutator), first_thread->GetTaskRunner());
  mutator_->RegisterAnimationWorkletMutator(
      WrapCrossThreadPersistent(second_mutator), first_thread->GetTaskRunner());

  EXPECT_CALL(*first_mutator, GetWorkletId())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(11));
  EXPECT_CALL(*first_mutator, MutateRef(_))
      .Times(1)
      .WillOnce(Return(new AnimationWorkletOutput()));
  EXPECT_CALL(*second_mutator, GetWorkletId())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(22));
  EXPECT_CALL(*second_mutator, MutateRef(_))
      .Times(1)
      .WillOnce(Return(new AnimationWorkletOutput()));
  EXPECT_CALL(*client_, SetMutationUpdateRef(_)).Times(2);

  EXPECT_TRUE(mutator_->MutateAsynchronously(
      CreateTestMutatorInput(), kNormalPriority, CreateTestCompleteCallback()));

  WaitForTestCompletion();
}

TEST_F(
    AnimationWorkletMutatorDispatcherImplAsyncTest,
    MutationUpdateInvokedCorrectlyWithTwoRegisteredAnimatorsOnDifferentThreads) {
  std::unique_ptr<NonMainThread> first_thread =
      CreateThread("FirstAnimationThread");
  MockAnimationWorkletMutator* first_mutator =
      MakeGarbageCollected<MockAnimationWorkletMutator>(
          first_thread->GetTaskRunner());

  std::unique_ptr<NonMainThread> second_thread =
      CreateThread("SecondAnimationThread");
  MockAnimationWorkletMutator* second_mutator =
      MakeGarbageCollected<MockAnimationWorkletMutator>(
          second_thread->GetTaskRunner());

  mutator_->RegisterAnimationWorkletMutator(
      WrapCrossThreadPersistent(first_mutator), first_thread->GetTaskRunner());
  mutator_->RegisterAnimationWorkletMutator(
      WrapCrossThreadPersistent(second_mutator),
      second_thread->GetTaskRunner());

  EXPECT_CALL(*first_mutator, GetWorkletId())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(11));
  EXPECT_CALL(*first_mutator, MutateRef(_))
      .Times(1)
      .WillOnce(Return(new AnimationWorkletOutput()));
  EXPECT_CALL(*second_mutator, GetWorkletId())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(22));
  EXPECT_CALL(*second_mutator, MutateRef(_))
      .Times(1)
      .WillOnce(Return(new AnimationWorkletOutput()));
  EXPECT_CALL(*client_, SetMutationUpdateRef(_)).Times(2);

  EXPECT_TRUE(mutator_->MutateAsynchronously(
      CreateTestMutatorInput(), kNormalPriority, CreateTestCompleteCallback()));

  WaitForTestCompletion();
}

TEST_F(AnimationWorkletMutatorDispatcherImplAsyncTest,
       MutationUpdateDroppedWhenBusy) {
  std::unique_ptr<NonMainThread> first_thread = CreateThread("FirstThread");
  MockAnimationWorkletMutator* first_mutator =
      MakeGarbageCollected<MockAnimationWorkletMutator>(
          first_thread->GetTaskRunner());
  mutator_->RegisterAnimationWorkletMutator(
      WrapCrossThreadPersistent(first_mutator), first_thread->GetTaskRunner());

  EXPECT_CALL(*first_mutator, GetWorkletId())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(11));
  EXPECT_CALL(*first_mutator, MutateRef(_))
      .Times(1)
      .WillOnce(Return(new AnimationWorkletOutput()));
  EXPECT_CALL(*client_, SetMutationUpdateRef(_)).Times(1);

  // Block Responses until all requests have been queued.
  first_mutator->BlockWorkletThread();
  // Response for first mutator call is blocked until after the second
  // call is sent.
  EXPECT_TRUE(mutator_->MutateAsynchronously(
      CreateTestMutatorInput(), kNormalPriority, CreateTestCompleteCallback()));
  // Second request dropped since busy processing first.
  EXPECT_FALSE(mutator_->MutateAsynchronously(CreateTestMutatorInput(),
                                              MutateQueuingStrategy::kDrop,
                                              CreateNotReachedCallback()));
  // Unblock first request.
  first_mutator->UnblockWorkletThread();

  WaitForTestCompletion();
}

TEST_F(AnimationWorkletMutatorDispatcherImplAsyncTest,
       MutationUpdateQueuedWhenBusy) {
  std::unique_ptr<NonMainThread> first_thread = CreateThread("FirstThread");

  MockAnimationWorkletMutator* first_mutator =
      MakeGarbageCollected<MockAnimationWorkletMutator>(
          first_thread->GetTaskRunner());
  mutator_->RegisterAnimationWorkletMutator(
      WrapCrossThreadPersistent(first_mutator), first_thread->GetTaskRunner());

  EXPECT_CALL(*first_mutator, GetWorkletId())
      .Times(AtLeast(2))
      .WillRepeatedly(Return(11));
  EXPECT_CALL(*first_mutator, MutateRef(_))
      .Times(2)
      .WillOnce(Return(new AnimationWorkletOutput()))
      .WillOnce(Return(new AnimationWorkletOutput()));
  EXPECT_CALL(*client_, SetMutationUpdateRef(_)).Times(2);
  EXPECT_CALL(*this, IntermediateResultCallbackRef()).Times(1);

  // Block Responses until all requests have been queued.
  first_mutator->BlockWorkletThread();
  // Response for first mutator call is blocked until after the second
  // call is sent.
  EXPECT_TRUE(mutator_->MutateAsynchronously(
      CreateTestMutatorInput(), kNormalPriority,
      CreateIntermediateResultCallback(MutateStatus::kCompletedWithUpdate)));
  // First request still processing, queue request.
  EXPECT_TRUE(mutator_->MutateAsynchronously(
      CreateTestMutatorInput(), kNormalPriority, CreateTestCompleteCallback()));
  // Unblock first request.
  first_mutator->UnblockWorkletThread();

  WaitForTestCompletion();
}

TEST_F(AnimationWorkletMutatorDispatcherImplAsyncTest,
       MutationUpdateQueueWithReplacementWhenBusy) {
  std::unique_ptr<NonMainThread> first_thread = CreateThread("FirstThread");

  MockAnimationWorkletMutator* first_mutator =
      MakeGarbageCollected<MockAnimationWorkletMutator>(
          first_thread->GetTaskRunner());
  mutator_->RegisterAnimationWorkletMutator(
      WrapCrossThreadPersistent(first_mutator), first_thread->GetTaskRunner());

  EXPECT_CALL(*first_mutator, GetWorkletId())
      .Times(AtLeast(2))
      .WillRepeatedly(Return(11));
  EXPECT_CALL(*first_mutator, MutateRef(_))
      .Times(2)
      .WillOnce(Return(new AnimationWorkletOutput()))
      .WillOnce(Return(new AnimationWorkletOutput()));
  EXPECT_CALL(*client_, SetMutationUpdateRef(_)).Times(2);
  EXPECT_CALL(*this, IntermediateResultCallbackRef()).Times(2);

  // Block Responses until all requests have been queued.
  first_mutator->BlockWorkletThread();
  // Response for first mutator call is blocked until after the second
  // call is sent.
  EXPECT_TRUE(mutator_->MutateAsynchronously(
      CreateTestMutatorInput(), kNormalPriority,
      CreateIntermediateResultCallback(MutateStatus::kCompletedWithUpdate)));
  // First request still processing, queue a second request, which will get
  // canceled by a third request.
  EXPECT_TRUE(mutator_->MutateAsynchronously(
      CreateTestMutatorInput(), kNormalPriority,
      CreateIntermediateResultCallback(MutateStatus::kCanceled)));
  // First request still processing, clobber second request in queue.
  EXPECT_TRUE(mutator_->MutateAsynchronously(
      CreateTestMutatorInput(), kNormalPriority, CreateTestCompleteCallback()));
  // Unblock first request.
  first_mutator->UnblockWorkletThread();

  WaitForTestCompletion();
}

TEST_F(AnimationWorkletMutatorDispatcherImplAsyncTest,
       MutationUpdateMultipleQueuesWhenBusy) {
  std::unique_ptr<NonMainThread> first_thread = CreateThread("FirstThread");

  MockAnimationWorkletMutator* first_mutator =
      MakeGarbageCollected<MockAnimationWorkletMutator>(
          first_thread->GetTaskRunner());
  mutator_->RegisterAnimationWorkletMutator(
      WrapCrossThreadPersistent(first_mutator), first_thread->GetTaskRunner());

  EXPECT_CALL(*first_mutator, GetWorkletId())
      .Times(AtLeast(3))
      .WillRepeatedly(Return(11));
  EXPECT_CALL(*first_mutator, MutateRef(_))
      .Times(3)
      .WillOnce(Return(new AnimationWorkletOutput()))
      .WillOnce(Return(new AnimationWorkletOutput()))
      .WillOnce(Return(new AnimationWorkletOutput()));
  EXPECT_CALL(*client_, SetMutationUpdateRef(_)).Times(3);
  EXPECT_CALL(*this, IntermediateResultCallbackRef()).Times(2);

  // Block Responses until all requests have been queued.
  first_mutator->BlockWorkletThread();
  // Response for first mutator call is blocked until after the second
  // call is sent.
  EXPECT_TRUE(mutator_->MutateAsynchronously(
      CreateTestMutatorInput(), kNormalPriority,
      CreateIntermediateResultCallback(MutateStatus::kCompletedWithUpdate)));
  // First request still processing, queue a second request.
  EXPECT_TRUE(mutator_->MutateAsynchronously(
      CreateTestMutatorInput(), kNormalPriority, CreateTestCompleteCallback()));
  // First request still processing. This request uses a separate queue from the
  // second request. It should not replace the second request but should be
  // dispatched ahead of the second request.
  EXPECT_TRUE(mutator_->MutateAsynchronously(
      CreateTestMutatorInput(), kHighPriority,
      CreateIntermediateResultCallback(MutateStatus::kCompletedWithUpdate)));
  // Unblock first request.
  first_mutator->UnblockWorkletThread();

  WaitForTestCompletion();
}

TEST_F(AnimationWorkletMutatorDispatcherImplAsyncTest, HistogramTester) {
  const char* histogram_name =
      "Animation.AnimationWorklet.Dispatcher.AsynchronousMutateDuration";
  base::HistogramTester histogram_tester;

  std::unique_ptr<base::TickClock> mock_clock =
      std::make_unique<base::SimpleTestTickClock>();
  base::SimpleTestTickClock* mock_clock_ptr =
      static_cast<base::SimpleTestTickClock*>(mock_clock.get());
  mutator_->SetClockForTesting(std::move(mock_clock));

  std::unique_ptr<NonMainThread> thread = CreateThread("MyThread");
  MockAnimationWorkletMutator* mutator =
      MakeGarbageCollected<MockAnimationWorkletMutator>(
          thread->GetTaskRunner());
  mutator_->RegisterAnimationWorkletMutator(WrapCrossThreadPersistent(mutator),
                                            thread->GetTaskRunner());

  EXPECT_CALL(*mutator, GetWorkletId())
      .Times(AtLeast(2))
      .WillRepeatedly(Return(11));
  EXPECT_CALL(*mutator, MutateRef(_))
      .Times(2)
      .WillOnce(Return(new AnimationWorkletOutput()))
      .WillOnce(Return(new AnimationWorkletOutput()));
  EXPECT_CALL(*client_, SetMutationUpdateRef(_)).Times(2);

  // Block Responses until all requests have been queued.
  mutator->BlockWorkletThread();

  base::TimeDelta time_delta = base::Milliseconds(10);

  // Expected Elapsed time is the sum of all clock advancements until unblocked,
  // which totals to 30 ms.
  EXPECT_TRUE(mutator_->MutateAsynchronously(
      CreateTestMutatorInput(), kHighPriority,
      CreateIntermediateResultCallback(MutateStatus::kCompletedWithUpdate)));
  mock_clock_ptr->Advance(time_delta);

  // This request will get stomped by the next request, but the start time is
  // preserved.
  EXPECT_TRUE(mutator_->MutateAsynchronously(
      CreateTestMutatorInput(), kNormalPriority,
      CreateIntermediateResultCallback(MutateStatus::kCanceled)));
  mock_clock_ptr->Advance(time_delta);

  // Replaces previous request. Since 10 ms has elapsed prior to replacing the
  // previous request, the expected elapsed time is 20 ms.
  EXPECT_TRUE(mutator_->MutateAsynchronously(
      CreateTestMutatorInput(), kNormalPriority, CreateTestCompleteCallback()));
  mock_clock_ptr->Advance(time_delta);

  mutator->UnblockWorkletThread();
  WaitForTestCompletion();

  histogram_tester.ExpectTotalCount(histogram_name, 2);
  // Times are in microseconds.
  histogram_tester.ExpectBucketCount(histogram_name, 20000, 1);
  histogram_tester.ExpectBucketCount(histogram_name, 30000, 1);
}

}  // namespace

}  // namespace blink
```