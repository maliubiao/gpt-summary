Response:
Let's break down the thought process for analyzing the provided C++ test file.

1. **Identify the Core Subject:** The file name `video_frame_sink_bundle_test.cc` immediately tells us this is a *test* file for something called `VideoFrameSinkBundle`. The location `blink/renderer/platform/graphics/` suggests it's related to rendering and graphics within the Blink engine (Chromium's rendering engine).

2. **Understand the Purpose of Unit Tests:** Unit tests are designed to isolate and verify the behavior of specific units of code (in this case, the `VideoFrameSinkBundle` class). They aim to ensure individual components work as expected.

3. **Scan for Key Classes and Functions:** Look for the main class being tested (`VideoFrameSinkBundle`) and any related mock objects or helper functions. In this file, we see:
    * `VideoFrameSinkBundle` (the class under test)
    * `MockEmbeddedFrameSinkProvider`
    * `MockFrameSinkBundle`
    * `MockCompositorFrameSinkClient`
    * `MockBeginFrameObserver`
    * Helper functions like `MakeBeginFrameInfo`

4. **Analyze Test Cases (TEST_F blocks):** Each `TEST_F` block represents a specific test scenario. Read the names of these tests carefully – they often describe the functionality being tested. For example:
    * `GetOrCreateSharedInstance`:  Likely tests the singleton pattern.
    * `Reconnect`: Tests how the bundle handles disconnections.
    * `PassThrough`: Checks if basic frame submission works.
    * `BatchSubmissionsDuringOnBeginFrame`:  Focuses on batching behavior.
    * Tests related to `DeliversBeginFrames...`:  Concerned with how `BeginFrame` signals are handled.

5. **Examine Mock Object Interactions (EXPECT_CALL):**  `EXPECT_CALL` is a crucial part of Google Mock. It specifies expected interactions with mock objects. This reveals how the `VideoFrameSinkBundle` is *supposed* to interact with its dependencies. For instance, `EXPECT_CALL(frame_sink_provider(), CreateFrameSinkBundle_).Times(1);` tells us the `VideoFrameSinkBundle` should call the `CreateFrameSinkBundle_` method on the `frame_sink_provider` exactly once in a certain scenario.

6. **Identify Key Concepts:**  Based on the class names, test names, and mock interactions, identify the core concepts involved:
    * **Frame Sinks:**  The `FrameSinkBundle` and `CompositorFrameSink` suggest a system for managing and submitting rendering frames.
    * **BeginFrame:**  The `BeginFrame` concept is central to the compositor's synchronization mechanism.
    * **Batching:** The "BatchSubmissions" test highlights an optimization technique.
    * **Client-Server Interaction:** The `FrameSinkBundleClient` indicates communication between the `VideoFrameSinkBundle` and something else (likely the compositor).
    * **Singleton Pattern:**  The `GetOrCreateSharedInstance` test points to the use of a singleton.
    * **Disconnection/Reconnection:**  The `Reconnect` test covers robustness.

7. **Relate to Web Concepts (JavaScript, HTML, CSS):**  Consider how the tested functionality might relate to the web platform. This often requires some background knowledge about how rendering works in browsers:
    * **Video Playback:** The name "VideoFrameSinkBundle" strongly suggests involvement in video rendering. HTML `<video>` elements are a primary use case.
    * **Compositing:** The terms "CompositorFrame" and "FrameSink" are key to the browser's compositing architecture, which handles layering and drawing web page elements. This directly relates to how HTML elements are rendered and how CSS properties (like transforms, opacity) are applied.
    * **Synchronization:** `BeginFrame` is crucial for synchronizing JavaScript animations, CSS transitions, and the rendering pipeline to avoid jank.

8. **Infer Logic and Assumptions:** Based on the tests, try to infer the logic within the `VideoFrameSinkBundle`. For example, the batching test suggests the bundle collects frame submissions during `OnBeginFrame` and sends them together. The `DeliversBeginFrames...` tests imply that the bundle manages whether clients need `BeginFrame` signals.

9. **Consider Potential Errors:** Think about common mistakes developers might make when using a class like `VideoFrameSinkBundle`. This often involves incorrect usage of its API, misunderstandings about its lifecycle, or race conditions.

10. **Structure the Explanation:** Organize the findings into logical sections (Functionality, Relation to Web Technologies, Logic/Assumptions, Potential Errors). Use clear and concise language. Provide specific examples where possible.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  "This might just be about submitting video frames."
* **Correction:**  Looking at the `CompositorFrame` and `BeginFrame` mentions, it's clear it's more general than *just* video, likely part of the overall compositing system, but with specific considerations for video.
* **Initial thought:** "The batching is just an optimization."
* **Refinement:**  The batching happening *during* `OnBeginFrame` suggests it's tied to the rendering synchronization process, not just a general optimization. This makes it more critical for correctness.
* **Considering web impact:** Initially focus on `<video>`, then broaden to consider how any animated content or layered element would rely on the underlying compositing mechanisms being tested.
这个C++文件 `video_frame_sink_bundle_test.cc` 是 Chromium Blink 引擎中 `VideoFrameSinkBundle` 类的单元测试文件。它的主要功能是验证 `VideoFrameSinkBundle` 类的各种行为和功能是否符合预期。

**以下是它测试的主要功能点：**

1. **单例模式 (`GetOrCreateSharedInstance`):**
   - 测试 `VideoFrameSinkBundle` 是否实现了单例模式，即对于同一个 `client_id`，只会创建一个实例，并且后续获取该实例会返回相同的对象。
   - **假设输入:** 多次调用 `VideoFrameSinkBundle::GetOrCreateSharedInstance(kTestClientId)`
   - **预期输出:** 所有调用返回指向同一个 `VideoFrameSinkBundle` 对象的指针。

2. **断线重连 (`Reconnect`):**
   - 测试当与底层 Viz 进程的连接断开时，`VideoFrameSinkBundle` 是否能够正确地被销毁并重新创建，从而重新建立连接。
   - **假设输入:**  模拟 `VideoFrameSinkBundle` 与 Viz 的连接断开。
   - **预期输出:** `VideoFrameSinkBundle` 对象被销毁并重新创建，生成新的 `FrameSinkBundleId`。

3. **帧提交透传 (`PassThrough`):**
   - 测试在没有特定优化或批处理的情况下，`VideoFrameSinkBundle` 是否能够将 CompositorFrame 和 DidNotProduceFrame 事件直接传递给底层的 Viz 组件。
   - **假设输入:** 调用 `SubmitCompositorFrame` 和 `DidNotProduceFrame`。
   - **预期输出:** 底层的 MockFrameSinkBundle 接收到相应的提交事件。

4. **BeginFrame 期间的帧提交批处理 (`BatchSubmissionsDuringOnBeginFrame`):**
   - 测试当在 `OnBeginFrame` 回调函数中提交 CompositorFrame 或 DidNotProduceFrame 时，`VideoFrameSinkBundle` 是否会将这些提交操作批处理，并在 `FlushNotifications` 时一次性发送。
   - **与 JavaScript, HTML, CSS 的关系:** 这涉及到浏览器渲染的同步机制。当 JavaScript 动画或 CSS 动画触发重绘时，渲染进程会收到 `BeginFrame` 信号。在这个 `BeginFrame` 处理过程中，如果需要提交新的渲染帧，`VideoFrameSinkBundle` 的批处理可以提高效率，避免多次独立的 IPC 调用。
   - **举例说明:** 考虑一个 JavaScript 动画，它在每个动画帧的回调中修改 DOM 导致重绘。在 `OnBeginFrame` 回调中，`VideoFrameSinkBundle` 会收集所有需要提交的帧（来自不同的视频或其他需要渲染的表面），然后一次性发送给 Compositor。
   - **假设输入:** 在多个 `CompositorFrameSinkClient` 的 `OnBeginFrame` 回调中调用 `SubmitCompositorFrame` 和 `DidNotProduceFrame`。
   - **预期输出:**  底层的 MockFrameSinkBundle 在 `FlushNotifications` 后接收到包含所有批处理的帧提交事件。

5. **BeginFrame 观察者 (`DeliversBeginFrames...`):**
   - 测试 `VideoFrameSinkBundle` 如何管理 `BeginFrameObserver`，以及何时发送 `OnBeginFrameCompletionEnabled` 和 `OnBeginFrameCompletion` 事件。这涉及到通知观察者 `BeginFrame` 是否被启用以及 `BeginFrame` 处理的完成情况。
   - **与 JavaScript, HTML, CSS 的关系:** `BeginFrame` 机制是浏览器渲染管道的关键部分，它协调 JavaScript 动画、CSS 动画和渲染更新。`BeginFrameObserver` 允许 Blink 引擎的其他部分了解 `BeginFrame` 的状态。
   - **举例说明:**  例如，一个视频播放器可能需要知道 `BeginFrame` 是否在运行，以同步视频帧的渲染。
   - **假设输入/输出:**
     - **输入:**  在没有 Sink 的情况下注册观察者。 **输出:** `OnBeginFrameCompletionEnabled(false)`
     - **输入:** 在有需要 `BeginFrame` 的 Sink 的情况下注册观察者。 **输出:** `OnBeginFrameCompletionEnabled(true)`
     - **输入:**  禁用所有需要 `BeginFrame` 的 Sink。 **输出:** `OnBeginFrameCompletionEnabled(false)`
     - **输入:**  添加需要 `BeginFrame` 的 Sink。 **输出:** `OnBeginFrameCompletionEnabled(true)`
     - **输入:**  调用 `FlushNotifications` 并且包含 `BeginFrameInfo`。 **输出:**  `OnBeginFrameCompletion` 被调用。
     - **输入:**  调用 `FlushNotifications` 并且不包含 `BeginFrameInfo`。 **输出:**  `OnBeginFrameCompletion` 不被调用。

**与 JavaScript, HTML, CSS 的关系总结:**

`VideoFrameSinkBundle` 负责管理渲染帧的提交，这与网页的动态内容渲染密切相关。当 JavaScript 操作 DOM 导致样式变化或动画更新，或者当 HTML5 视频需要渲染新的帧时，都会涉及到 `VideoFrameSinkBundle` 的功能。它确保渲染更新能够有效地传递到 Compositor 进程进行最终的合成和绘制。

**用户或编程常见的错误举例：**

1. **在错误的线程调用 `VideoFrameSinkBundle` 的方法:** `VideoFrameSinkBundle` 的某些操作可能需要在特定的线程上执行（通常是 Compositor 线程）。如果在错误的线程调用这些方法，可能会导致崩溃或未定义的行为。
   - **错误示例:** 在 JavaScript 的 `requestAnimationFrame` 回调中直接同步调用 `VideoFrameSinkBundle` 的方法，而没有确保该回调在 Compositor 线程上执行。

2. **没有正确处理 `BeginFrame` 信号:**  如果组件需要与渲染管道同步，它需要正确地设置 `needs_begin_frame` 标志，并响应 `BeginFrame` 信号。没有正确处理可能导致动画卡顿或不同步。
   - **错误示例:** 一个自定义的 Web 组件需要进行动画渲染，但没有设置 `needs_begin_frame`，导致 Compositor 不会为其生成 `BeginFrame` 信号，动画无法启动。

3. **过早或过晚地提交 CompositorFrame:**  CompositorFrame 的提交需要在正确的时机进行。过早提交可能会导致渲染不连贯，过晚提交则可能导致帧丢失。
   - **错误示例:** 在接收到 `BeginFrame` 信号之前就提交了 CompositorFrame。

4. **忘记在不再需要时取消注册 `BeginFrameObserver`:**  如果一个组件注册了 `BeginFrameObserver` 但在不再需要时忘记取消注册，可能会导致不必要的资源消耗和回调。

总而言之， `video_frame_sink_bundle_test.cc` 这个测试文件通过各种测试用例，确保 `VideoFrameSinkBundle` 类能够正确地管理渲染帧的提交和 `BeginFrame` 信号的处理，这对于 Chromium 浏览器高效且流畅地渲染网页内容至关重要。

### 提示词
```
这是目录为blink/renderer/platform/graphics/video_frame_sink_bundle_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/video_frame_sink_bundle.h"

#include <memory>
#include <tuple>
#include <utility>

#include "base/run_loop.h"
#include "base/test/mock_callback.h"
#include "base/test/task_environment.h"
#include "base/time/time.h"
#include "base/unguessable_token.h"
#include "components/viz/common/frame_sinks/begin_frame_args.h"
#include "components/viz/common/frame_timing_details.h"
#include "components/viz/common/surfaces/frame_sink_bundle_id.h"
#include "components/viz/common/surfaces/frame_sink_id.h"
#include "components/viz/common/surfaces/local_surface_id.h"
#include "components/viz/test/compositor_frame_helpers.h"
#include "services/viz/public/mojom/compositing/frame_sink_bundle.mojom-blink.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/graphics/test/mock_compositor_frame_sink.h"
#include "third_party/blink/renderer/platform/graphics/test/mock_compositor_frame_sink_client.h"
#include "third_party/blink/renderer/platform/graphics/test/mock_embedded_frame_sink_provider.h"
#include "third_party/blink/renderer/platform/graphics/test/mock_frame_sink_bundle.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {
namespace {

using ::testing::AllOf;
using ::testing::ElementsAre;
using ::testing::UnorderedElementsAre;

const uint32_t kTestClientId = 1;

const viz::FrameSinkId kTestVideoSinkId1(kTestClientId, 2);
const viz::FrameSinkId kTestVideoSinkId2(kTestClientId, 3);
const viz::FrameSinkId kTestVideoSinkId3(kTestClientId, 4);

class MockBeginFrameObserver : public VideoFrameSinkBundle::BeginFrameObserver {
 public:
  MOCK_METHOD(void, OnBeginFrameCompletion, (), (override));
  MOCK_METHOD(void, OnBeginFrameCompletionEnabled, (bool), (override));
};

MATCHER(IsEmpty, "") {
  return arg.IsEmpty();
}
MATCHER(IsFrame, "") {
  return arg->data->which() ==
         viz::mojom::blink::BundledFrameSubmissionData::Tag::kFrame;
}
MATCHER(IsDidNotProduceFrame, "") {
  return arg->data->which() == viz::mojom::blink::BundledFrameSubmissionData::
                                   Tag::kDidNotProduceFrame;
}
MATCHER_P(ForSink, sink_id, "") {
  return arg->sink_id == sink_id;
}

viz::mojom::blink::BeginFrameInfoPtr MakeBeginFrameInfo(uint32_t sink_id) {
  return viz::mojom::blink::BeginFrameInfo::New(
      sink_id,
      viz::BeginFrameArgs::Create(BEGINFRAME_FROM_HERE, 1, 1, base::TimeTicks(),
                                  base::TimeTicks(), base::TimeDelta(),
                                  viz::BeginFrameArgs::NORMAL),
      WTF::HashMap<uint32_t, viz::FrameTimingDetails>(),
      /*frame_ack=*/false, WTF::Vector<viz::ReturnedResource>());
}

class MockFrameSinkBundleClient
    : public viz::mojom::blink::FrameSinkBundleClient {
 public:
  ~MockFrameSinkBundleClient() override = default;

  // viz::mojom::blink::FrameSinkBundleClient implementation:
  MOCK_METHOD3(
      FlushNotifications,
      void(WTF::Vector<viz::mojom::blink::BundledReturnedResourcesPtr> acks,
           WTF::Vector<viz::mojom::blink::BeginFrameInfoPtr> begin_frames,
           WTF::Vector<viz::mojom::blink::BundledReturnedResourcesPtr>
               reclaimed_resources));
  MOCK_METHOD2(OnBeginFramePausedChanged, void(uint32_t sink_id, bool paused));
  MOCK_METHOD2(OnCompositorFrameTransitionDirectiveProcessed,
               void(uint32_t sink_id, uint32_t sequence_id));
};

const viz::LocalSurfaceId kTestSurfaceId(
    1,
    base::UnguessableToken::CreateForTesting(1, 2));

class VideoFrameSinkBundleTest : public testing::Test {
 public:
  VideoFrameSinkBundleTest() {
    VideoFrameSinkBundle::SetFrameSinkProviderForTesting(
        &frame_sink_provider());
  }

  ~VideoFrameSinkBundleTest() override {
    VideoFrameSinkBundle::SetFrameSinkProviderForTesting(nullptr);
    VideoFrameSinkBundle::DestroySharedInstanceForTesting();
  }

  void CreateTestBundle() {
    EXPECT_CALL(frame_sink_provider(), CreateFrameSinkBundle_).Times(1);
    test_bundle();
  }

  VideoFrameSinkBundle& test_bundle() {
    return VideoFrameSinkBundle::GetOrCreateSharedInstance(kTestClientId);
  }

  MockEmbeddedFrameSinkProvider& frame_sink_provider() {
    return mock_frame_sink_provider_;
  }

  MockFrameSinkBundleClient& mock_bundle_client() {
    return mock_bundle_client_;
  }

  MockFrameSinkBundle& mock_frame_sink_bundle() {
    return frame_sink_provider().mock_frame_sink_bundle();
  }

 private:
  MockEmbeddedFrameSinkProvider mock_frame_sink_provider_;
  MockFrameSinkBundleClient mock_bundle_client_;
  base::test::TaskEnvironment task_environment_;
};

TEST_F(VideoFrameSinkBundleTest, GetOrCreateSharedInstance) {
  // Verify that GetOrCreateSharedInstance lazily initializes an instance.
  EXPECT_CALL(frame_sink_provider(), CreateFrameSinkBundle_).Times(1);
  VideoFrameSinkBundle& bundle =
      VideoFrameSinkBundle::GetOrCreateSharedInstance(kTestClientId);

  // And that acquiring an instance with the same client ID reuses the existing
  // instance.
  VideoFrameSinkBundle& other_bundle =
      VideoFrameSinkBundle::GetOrCreateSharedInstance(kTestClientId);
  EXPECT_EQ(&other_bundle, &bundle);
}

TEST_F(VideoFrameSinkBundleTest, Reconnect) {
  // Verifies that VideoFrameSinkBundle is destroyed and recreated if
  // disconnected, reestablishing a connection to Viz as a result.
  CreateTestBundle();
  viz::FrameSinkBundleId first_bundle_id = test_bundle().bundle_id();

  base::RunLoop loop;
  test_bundle().set_disconnect_handler_for_testing(loop.QuitClosure());
  mock_frame_sink_bundle().Disconnect();
  loop.Run();

  EXPECT_CALL(frame_sink_provider(), CreateFrameSinkBundle_)
      .Times(1)
      .WillOnce([&] { loop.Quit(); });

  viz::FrameSinkBundleId second_bundle_id = test_bundle().bundle_id();
  EXPECT_EQ(first_bundle_id.client_id(), second_bundle_id.client_id());
  EXPECT_NE(first_bundle_id.bundle_id(), second_bundle_id.bundle_id());
}

TEST_F(VideoFrameSinkBundleTest, PassThrough) {
  // Verifies that as a safe default, VideoFrameSinkBundle passes frame
  // submissions through to Viz without any batching.
  CreateTestBundle();
  VideoFrameSinkBundle& bundle = test_bundle();
  bundle.SubmitCompositorFrame(
      2, kTestSurfaceId, viz::MakeDefaultCompositorFrame(), std::nullopt, 0);
  EXPECT_CALL(mock_frame_sink_bundle(),
              Submit(ElementsAre(AllOf(IsFrame(), ForSink(2u)))))
      .Times(1);
  mock_frame_sink_bundle().FlushReceiver();

  bundle.DidNotProduceFrame(3, viz::BeginFrameAck(1, 2, false));
  EXPECT_CALL(mock_frame_sink_bundle(),
              Submit(ElementsAre(AllOf(IsDidNotProduceFrame(), ForSink(3u)))));
  mock_frame_sink_bundle().FlushReceiver();
}

TEST_F(VideoFrameSinkBundleTest, BatchSubmissionsDuringOnBeginFrame) {
  // Verifies that submitted compositor frames (or DidNotProduceFrames) are
  // batched when submitted during an OnBeginFrame handler, and flushed
  // afterwords.
  CreateTestBundle();
  VideoFrameSinkBundle& bundle = test_bundle();

  MockCompositorFrameSinkClient mock_client1;
  MockCompositorFrameSinkClient mock_client2;
  MockCompositorFrameSinkClient mock_client3;
  mojo::Remote<mojom::blink::EmbeddedFrameSinkProvider> provider;
  mojo::Remote<viz::mojom::blink::CompositorFrameSink> sink1;
  mojo::Remote<viz::mojom::blink::CompositorFrameSink> sink2;
  mojo::Remote<viz::mojom::blink::CompositorFrameSink> sink3;
  mojo::Receiver<viz::mojom::blink::CompositorFrameSinkClient> receiver1{
      &mock_client1};
  mojo::Receiver<viz::mojom::blink::CompositorFrameSinkClient> receiver2{
      &mock_client2};
  mojo::Receiver<viz::mojom::blink::CompositorFrameSinkClient> receiver3{
      &mock_client3};
  std::ignore = provider.BindNewPipeAndPassReceiver();
  bundle.AddClient(kTestVideoSinkId1, &mock_client1, provider, receiver1,
                   sink1);
  bundle.AddClient(kTestVideoSinkId2, &mock_client2, provider, receiver2,
                   sink2);
  bundle.AddClient(kTestVideoSinkId3, &mock_client3, provider, receiver3,
                   sink3);

  // All clients will submit a frame synchronously within OnBeginFrame.
  EXPECT_CALL(mock_client1, OnBeginFrame).Times(1).WillOnce([&] {
    bundle.SubmitCompositorFrame(kTestVideoSinkId1.sink_id(), kTestSurfaceId,
                                 viz::MakeDefaultCompositorFrame(),
                                 std::nullopt, 0);
  });
  EXPECT_CALL(mock_client2, OnBeginFrame).Times(1).WillOnce([&] {
    bundle.DidNotProduceFrame(kTestVideoSinkId2.sink_id(),
                              viz::BeginFrameAck(1, 1, false));
  });
  EXPECT_CALL(mock_client3, OnBeginFrame).Times(1).WillOnce([&] {
    bundle.SubmitCompositorFrame(kTestVideoSinkId3.sink_id(), kTestSurfaceId,
                                 viz::MakeDefaultCompositorFrame(),
                                 std::nullopt, 0);
  });

  WTF::Vector<viz::mojom::blink::BeginFrameInfoPtr> begin_frames;
  begin_frames.push_back(MakeBeginFrameInfo(kTestVideoSinkId1.sink_id()));
  begin_frames.push_back(MakeBeginFrameInfo(kTestVideoSinkId2.sink_id()));
  begin_frames.push_back(MakeBeginFrameInfo(kTestVideoSinkId3.sink_id()));
  bundle.FlushNotifications({}, std::move(begin_frames), {});

  EXPECT_CALL(
      mock_frame_sink_bundle(),
      Submit(UnorderedElementsAre(
          AllOf(IsFrame(), ForSink(kTestVideoSinkId1.sink_id())),
          AllOf(IsDidNotProduceFrame(), ForSink(kTestVideoSinkId2.sink_id())),
          AllOf(IsFrame(), ForSink(kTestVideoSinkId3.sink_id())))))
      .Times(1);
  mock_frame_sink_bundle().FlushReceiver();
}

TEST_F(VideoFrameSinkBundleTest,
       DeliversBeginFramesDisabledWithoutSinksOnRegistration) {
  CreateTestBundle();
  VideoFrameSinkBundle& bundle = test_bundle();
  auto observer = std::make_unique<MockBeginFrameObserver>();
  EXPECT_CALL(*observer, OnBeginFrameCompletionEnabled(false));
  bundle.SetBeginFrameObserver(std::move(observer));
}

TEST_F(VideoFrameSinkBundleTest,
       DeliversBeginFramesEnabledWithSinkOnRegistration) {
  CreateTestBundle();
  VideoFrameSinkBundle& bundle = test_bundle();
  auto observer = std::make_unique<MockBeginFrameObserver>();
  EXPECT_CALL(*observer, OnBeginFrameCompletionEnabled(true));
  bundle.SetNeedsBeginFrame(kTestVideoSinkId1.sink_id(), true);
  bundle.SetBeginFrameObserver(std::move(observer));
}

TEST_F(VideoFrameSinkBundleTest, DeliversBeginFramesDisabledOnSinksDisabled) {
  CreateTestBundle();
  VideoFrameSinkBundle& bundle = test_bundle();
  bundle.SetNeedsBeginFrame(kTestVideoSinkId1.sink_id(), true);
  auto observer = std::make_unique<MockBeginFrameObserver>();
  MockBeginFrameObserver* observer_ptr = observer.get();
  bundle.SetBeginFrameObserver(std::move(observer));
  EXPECT_CALL(*observer_ptr, OnBeginFrameCompletionEnabled(false));
  bundle.SetNeedsBeginFrame(kTestVideoSinkId1.sink_id(), false);
}

TEST_F(VideoFrameSinkBundleTest, DeliversBeginFramesEnabledOnSinkAdded) {
  CreateTestBundle();
  VideoFrameSinkBundle& bundle = test_bundle();
  auto observer = std::make_unique<MockBeginFrameObserver>();
  MockBeginFrameObserver* observer_ptr = observer.get();
  bundle.SetBeginFrameObserver(std::move(observer));
  EXPECT_CALL(*observer_ptr, OnBeginFrameCompletionEnabled(true));
  bundle.SetNeedsBeginFrame(kTestVideoSinkId1.sink_id(), true);
}

TEST_F(VideoFrameSinkBundleTest,
       DeliversBeginFrameCompletionOnFlushWithBeginFrames) {
  CreateTestBundle();
  VideoFrameSinkBundle& bundle = test_bundle();

  auto make_begin_frames = [] {
    WTF::Vector<viz::mojom::blink::BeginFrameInfoPtr> begin_frames;
    begin_frames.push_back(MakeBeginFrameInfo(kTestVideoSinkId1.sink_id()));
    return begin_frames;
  };

  auto observer = std::make_unique<MockBeginFrameObserver>();
  EXPECT_CALL(*observer, OnBeginFrameCompletion).Times(2);
  bundle.SetBeginFrameObserver(std::move(observer));
  bundle.FlushNotifications({}, make_begin_frames(), {});
  bundle.FlushNotifications({}, make_begin_frames(), {});
}

TEST_F(VideoFrameSinkBundleTest,
       OmitsBeginFrameCompletionOnceOnFlushWithoutBeginFrames) {
  CreateTestBundle();
  VideoFrameSinkBundle& bundle = test_bundle();
  auto observer = std::make_unique<MockBeginFrameObserver>();
  EXPECT_CALL(*observer, OnBeginFrameCompletion).Times(0);
  bundle.SetBeginFrameObserver(std::move(observer));
  bundle.FlushNotifications({}, {}, {});
}

}  // namespace
}  // namespace blink
```