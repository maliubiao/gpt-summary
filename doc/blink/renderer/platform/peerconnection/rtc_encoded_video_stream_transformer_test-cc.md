Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The filename `rtc_encoded_video_stream_transformer_test.cc` immediately suggests this file is a test suite for a class named `RTCEncodedVideoStreamTransformer`. The `test.cc` suffix is a common convention.

2. **Examine Includes:** The included headers provide significant clues about the class's functionality and dependencies:
    *  `<stdint.h>`, `<memory>`, `<vector>`: Standard C++ for basic types and containers.
    *  `base/memory/...`, `base/task/...`, `base/test/...`:  Indicates the use of Chromium's base library for memory management, threading, and testing infrastructure (specifically `base::test::TaskEnvironment`).
    *  `testing/gmock/...`, `testing/gtest/...`:  Confirms this is a unit test file using Google Mock and Google Test frameworks.
    *  `third_party/blink/...`: This is the crucial part. It points to Blink-specific components. `platform/peerconnection/` strongly suggests involvement with WebRTC's PeerConnection API.
    *  `rtc_encoded_video_stream_transformer.h`:  This confirms the class under test.
    *  `rtc_scoped_refptr_cross_thread_copier.h`, `scheduler/...`, `wtf/...`:  Highlights the use of cross-threading mechanisms and Blink's `WTF` (Web Template Framework) utilities.
    *  `third_party/webrtc/api/...`: Direct interaction with WebRTC's API, specifically `FrameTransformerInterface` and `TransformableVideoFrame`.
    *  `third_party/webrtc/rtc_base/...`: More low-level WebRTC components.

3. **Analyze the Test Structure:**
    * **Namespaces:** The code is within the `blink` namespace and an anonymous namespace `{}`, which is common for test-specific helpers.
    * **Helper Classes:**  The presence of `MockWebRtcTransformedFrameCallback`, `MockTransformerCallbackHolder`, and `MockMetronome` strongly indicates the use of mocks to isolate the `RTCEncodedVideoStreamTransformer` during testing. The `MOCK_METHOD` macros confirm this.
    * **Test Fixture:** The `RTCEncodedVideoStreamTransformerTest` class, parameterized by a boolean, sets up the environment for multiple test cases. The `SetUp` and `TearDown` methods handle initialization and cleanup. The parameterization suggests testing with and without a `Metronome`.
    * **Individual Tests (using `TEST_P`):**  Each `TEST_P` function focuses on testing a specific aspect of the `RTCEncodedVideoStreamTransformer`. The names of the tests (e.g., `TransformerForwardsFrameToTransformerCallback`) are descriptive of the functionality being verified.
    * **Assertions and Expectations:**  The tests use `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_CALL`, and `ASSERT_TRUE` to make assertions about the behavior of the class under test and its interactions with the mocked dependencies.

4. **Infer Functionality from Tests:** By examining the test names and the mocked interactions, we can deduce the core responsibilities of `RTCEncodedVideoStreamTransformer`:
    * **Forwarding Encoded Video Frames:**  Tests like `TransformerForwardsFrameToTransformerCallback` and `TransformerForwardsFrameToWebRTC` indicate its role in routing encoded video frames.
    * **Interacting with a Transformer Callback:**  The "TransformerCallback" is clearly a mechanism for custom processing of the encoded frames.
    * **Interacting with a WebRTC Sink:**  The "WebRTC callback" represents the destination for transformed frames within the WebRTC pipeline.
    * **Handling SSRC:** The `IgnoresSsrcForSinglecast` test suggests it might handle Source Synchronization Request identifiers, but has special behavior for single-cast scenarios.
    * **Short-Circuiting:** Tests involving `StartShortCircuiting` indicate a mechanism to bypass the transformer and send frames directly to the sink.
    * **Metronome Integration:** The parameterized tests and the `WaitsForMetronomeTick` test reveal that the class can optionally synchronize frame processing with a `Metronome`.
    * **Buffering:** Tests involving "buffered" frames imply the class can temporarily store frames before processing or forwarding them.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** This is the primary interface for WebRTC in browsers. JavaScript code using the `RTCSender` or `RTCReceiver` APIs would be the entity that *uses* the `RTCEncodedVideoStreamTransformer` indirectly. The JavaScript would set up the transform if desired.
    * **HTML:** HTML provides the `<video>` element, which is where the decoded video stream is ultimately displayed. HTML doesn't directly interact with the transformer.
    * **CSS:** CSS styles the video element's appearance but has no bearing on the frame transformation process.

6. **Identify Logic and Assumptions:**
    * **Assumption:** The tests assume the existence of a WebRTC pipeline and the roles of senders and receivers.
    * **Logic:** The tests check the order of operations, whether callbacks are invoked correctly, and how the class handles different states (e.g., before/after setting a transformer, before/after short-circuiting).

7. **Consider Potential User/Programming Errors:**
    * **Incorrect Callback Registration:**  Failing to register a transformer callback when needed would mean frames aren't processed.
    * **Misunderstanding Short-Circuiting:** Assuming the transformer still processes frames after short-circuiting is a mistake.
    * **Thread Safety Issues:** While the tests use cross-thread mechanisms, incorrect usage in the actual application code could lead to race conditions if the transformer callback isn't thread-safe.
    * **Metronome Misconfiguration:** If a metronome is used, but its tick rate isn't aligned with the frame rate, it could cause delays or dropped frames.

By following this systematic approach, we can thoroughly understand the purpose, functionality, and context of the given C++ test file. The key is to leverage the information provided by the code itself (includes, class names, test names, mocking) and connect it to the broader WebRTC and web development landscape.
这个文件 `rtc_encoded_video_stream_transformer_test.cc` 是 Chromium Blink 引擎中用于测试 `RTCEncodedVideoStreamTransformer` 类的单元测试文件。 `RTCEncodedVideoStreamTransformer` 的主要功能是**作为一个中间层，允许在 WebRTC 的视频编码和解码过程中对视频帧进行自定义处理。**

更具体地说，这个测试文件验证了以下 `RTCEncodedVideoStreamTransformer` 的功能：

**核心功能:**

1. **转发帧到 Transformer 回调:**  测试验证了当设置了自定义的 transformer 回调函数后，编码后的视频帧能够被正确地传递到这个回调函数进行处理。
2. **转发帧到 WebRTC Sink:** 测试验证了当没有设置自定义的 transformer 回调函数时，或者在自定义处理之后，编码后的视频帧能够被正确地转发回 WebRTC 的接收端（sink）。
3. **处理 SSRC:**  测试了当使用单播时，即使传入的帧的 SSRC (Source Synchronization Request) 不匹配，帧仍然能够被正确处理。这表明在单播场景下，SSRC 可能不是关键的路由依据。
4. **短路 (Short-Circuiting) 机制:** 测试了 `RTCEncodedVideoStreamTransformer` 的短路功能。当启动短路后，后续的帧将不再经过 transformer 的处理，而是直接发送到 WebRTC sink。
5. **处理延迟注册的回调:** 测试了在启动短路后再注册回调函数的情况，确保新的回调函数也能接收到短路的通知。
6. **与 Metronome 的协同工作 (可选):**  测试了当提供 `Metronome` 对象时，帧的处理会等待 `Metronome` 的 "tick" 事件，从而实现帧处理的同步。这在某些需要精确时间控制的场景下很有用。
7. **缓冲帧:** 测试了在启动短路或设置 transformer 回调之前到达的帧会被缓冲，并在条件满足时被处理或发送。

**与 JavaScript, HTML, CSS 的关系:**

`RTCEncodedVideoStreamTransformer` 本身是一个 C++ 类，直接运行在浏览器的渲染进程中。它不直接与 JavaScript, HTML, CSS 代码交互。但是，它的功能是作为 WebRTC API 的底层实现的一部分，而 WebRTC API 暴露给 JavaScript，从而让 Web 开发者可以使用这些功能。

**举例说明:**

1. **JavaScript:**  Web 开发者可以使用 JavaScript 的 `RTCRtpSender` 或 `RTCRtpReceiver` 对象的 `transform` 属性来设置一个 `RTCRtpScriptTransform` 对象，从而将自定义的 JavaScript 代码注入到 WebRTC 的媒体处理管道中。这个 JavaScript 代码最终会通过某种机制（例如 MessagePort）与 C++ 层的 `RTCEncodedVideoStreamTransformer` 进行交互。

   **假设输入 (JavaScript):**

   ```javascript
   const sender = peerConnection.addTrack(videoTrack).getSenders()[0];
   const transformStream = new TransformStream({
     transform(chunk, controller) {
       // 自定义处理编码后的视频帧 (chunk)
       // 例如，添加水印
       const encodedData = new Uint8Array(chunk.data);
       // ... 修改 encodedData ...
       chunk.data = encodedData.buffer;
       controller.enqueue(chunk);
     }
   });
   sender.transform = transformStream;
   ```

   **输出 (C++ 侧的 `RTCEncodedVideoStreamTransformer`):**

   当发送端发送视频帧时，`RTCEncodedVideoStreamTransformer` 会接收到编码后的视频帧数据。如果设置了 JavaScript 的 `transform`，`RTCEncodedVideoStreamTransformer` 会将帧数据传递给对应的 C++ 层处理逻辑，该逻辑会与 JavaScript 代码通过消息传递进行交互，最终执行 JavaScript 中定义的 `transform` 函数。

2. **HTML:** HTML 中的 `<video>` 标签用于展示 WebRTC 接收到的视频流。 `RTCEncodedVideoStreamTransformer` 处理的是发送端的编码过程，因此与 HTML 没有直接的功能关联。

3. **CSS:** CSS 用于控制 HTML 元素的样式，与 `RTCEncodedVideoStreamTransformer` 的功能完全无关。

**逻辑推理 (假设输入与输出):**

假设我们有一个测试用例，验证 `RTCEncodedVideoStreamTransformer` 能正确地将帧转发到已注册的 transformer 回调。

**假设输入:**

* 创建一个 `RTCEncodedVideoStreamTransformer` 实例。
* 创建一个 mock 的 `MockTransformerCallbackHolder` 实例，用于接收回调。
* 使用 `SetTransformerCallback` 方法注册 `MockTransformerCallbackHolder` 的 `OnEncodedFrame` 方法作为回调。
* 创建一个 mock 的编码后的视频帧 `mock_frame`。
* 调用 `encoded_video_stream_transformer_.Delegate()->Transform(mock_frame)` 模拟 WebRTC 发送帧。

**预期输出:**

* `MockTransformerCallbackHolder` 的 `OnEncodedFrame` 方法会被调用一次。
* 传递给 `OnEncodedFrame` 的参数是一个指向编码后视频帧的智能指针。

**用户或编程常见的使用错误:**

1. **忘记注册 Transformer 回调:**  Web 开发者如果想要自定义处理编码后的视频帧，但忘记在 JavaScript 中设置 `transform` 属性，或者 C++ 代码中没有正确设置回调，那么帧将不会经过自定义处理逻辑。
2. **在短路后仍然尝试修改 Transformer 回调:** 一旦启动了短路，尝试修改 transformer 回调将不会有效果，因为帧已经不再经过 transformer 处理。
3. **错误地理解 Metronome 的作用:**  如果错误地认为 `Metronome` 会自动处理帧，而没有正确地触发 `Metronome` 的 "tick" 事件，可能会导致帧处理延迟或停滞。
4. **线程安全问题:** 自定义的 transformer 回调函数需要在多线程环境下安全地运行，否则可能导致数据竞争或其他并发问题。开发者需要在回调函数中注意同步和互斥。
5. **资源管理错误:** 如果自定义的 transformer 回调函数中涉及到资源的分配和释放，开发者需要确保正确地管理这些资源，避免内存泄漏或其他资源泄露。例如，如果修改了帧数据，需要正确地分配和释放内存。

总而言之，`rtc_encoded_video_stream_transformer_test.cc` 通过一系列单元测试，确保了 `RTCEncodedVideoStreamTransformer` 这个关键的 WebRTC 组件能够按照预期工作，为 Web 开发者提供可靠的视频帧处理能力。虽然它本身是 C++ 代码，但它的功能直接支撑着 JavaScript WebRTC API 的实现。

### 提示词
```
这是目录为blink/renderer/platform/peerconnection/rtc_encoded_video_stream_transformer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/peerconnection/rtc_encoded_video_stream_transformer.h"

#include <stdint.h>

#include <memory>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/test/task_environment.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_scoped_refptr_cross_thread_copier.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/webrtc/api/array_view.h"
#include "third_party/webrtc/api/frame_transformer_interface.h"
#include "third_party/webrtc/api/test/mock_transformable_video_frame.h"
#include "third_party/webrtc/api/units/time_delta.h"
#include "third_party/webrtc/rtc_base/ref_counted_object.h"

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SaveArg;

namespace blink {

namespace {

const uint32_t kSSRC = 1;
const uint32_t kNonexistentSSRC = 0;

class MockWebRtcTransformedFrameCallback
    : public webrtc::TransformedFrameCallback {
 public:
  MOCK_METHOD1(OnTransformedFrame,
               void(std::unique_ptr<webrtc::TransformableFrameInterface>));
  MOCK_METHOD0(StartShortCircuiting, void());
};

class MockTransformerCallbackHolder {
 public:
  MOCK_METHOD1(OnEncodedFrame,
               void(std::unique_ptr<webrtc::TransformableVideoFrameInterface>));
};

class MockMetronome : public webrtc::Metronome {
 public:
  MOCK_METHOD(void,
              RequestCallOnNextTick,
              (absl::AnyInvocable<void() &&> callback),
              (override));
  MOCK_METHOD(webrtc::TimeDelta, TickPeriod, (), (const, override));
};

std::unique_ptr<webrtc::MockTransformableVideoFrame> CreateMockFrame() {
  auto mock_frame =
      std::make_unique<NiceMock<webrtc::MockTransformableVideoFrame>>();
  ON_CALL(*mock_frame.get(), GetSsrc).WillByDefault(Return(kSSRC));
  return mock_frame;
}

}  // namespace

// Parameterized by bool whether to suply a metronome or not.
class RTCEncodedVideoStreamTransformerTest
    : public testing::TestWithParam<bool> {
 public:
  RTCEncodedVideoStreamTransformerTest()
      : main_task_runner_(
            blink::scheduler::GetSingleThreadTaskRunnerForTesting()),
        webrtc_task_runner_(base::ThreadPool::CreateSingleThreadTaskRunner({})),
        webrtc_callback_(
            new rtc::RefCountedObject<MockWebRtcTransformedFrameCallback>()),
        metronome_(GetParam() ? new NiceMock<MockMetronome>() : nullptr),
        encoded_video_stream_transformer_(main_task_runner_,
                                          absl::WrapUnique(metronome_.get())) {}

  void SetUp() override {
    EXPECT_FALSE(
        encoded_video_stream_transformer_.HasTransformedFrameSinkCallback(
            kSSRC));
    encoded_video_stream_transformer_.RegisterTransformedFrameSinkCallback(
        webrtc_callback_, kSSRC);
    EXPECT_TRUE(
        encoded_video_stream_transformer_.HasTransformedFrameSinkCallback(
            kSSRC));
    EXPECT_FALSE(
        encoded_video_stream_transformer_.HasTransformedFrameSinkCallback(
            kNonexistentSSRC));
    if (GetParam()) {
      ON_CALL(*metronome_, RequestCallOnNextTick(_))
          .WillByDefault([](absl::AnyInvocable<void()&&> callback) {
            std::move(callback)();
          });
    }
  }

  void TearDown() override {
    metronome_ = nullptr;
    encoded_video_stream_transformer_.UnregisterTransformedFrameSinkCallback(
        kSSRC);
    EXPECT_FALSE(
        encoded_video_stream_transformer_.HasTransformedFrameSinkCallback(
            kSSRC));
  }

 protected:
  base::test::TaskEnvironment task_environment_;
  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> webrtc_task_runner_;
  rtc::scoped_refptr<MockWebRtcTransformedFrameCallback> webrtc_callback_;
  MockTransformerCallbackHolder mock_transformer_callback_holder_;
  raw_ptr<MockMetronome> metronome_;
  RTCEncodedVideoStreamTransformer encoded_video_stream_transformer_;
};

INSTANTIATE_TEST_SUITE_P(MetronomeAlignment,
                         RTCEncodedVideoStreamTransformerTest,
                         testing::Values(true, false));

TEST_P(RTCEncodedVideoStreamTransformerTest,
       TransformerForwardsFrameToTransformerCallback) {
  EXPECT_FALSE(encoded_video_stream_transformer_.HasTransformerCallback());
  encoded_video_stream_transformer_.SetTransformerCallback(
      WTF::CrossThreadBindRepeating(
          &MockTransformerCallbackHolder::OnEncodedFrame,
          WTF::CrossThreadUnretained(&mock_transformer_callback_holder_)));
  EXPECT_TRUE(encoded_video_stream_transformer_.HasTransformerCallback());

  EXPECT_CALL(mock_transformer_callback_holder_, OnEncodedFrame);
  // Frames are pushed to the RTCEncodedVideoStreamTransformer via its delegate,
  // which  would normally be registered with a WebRTC sender or receiver.
  // In this test, manually send the frame to the transformer on the simulated
  // WebRTC thread.
  PostCrossThreadTask(
      *webrtc_task_runner_, FROM_HERE,
      CrossThreadBindOnce(&webrtc::FrameTransformerInterface::Transform,
                          encoded_video_stream_transformer_.Delegate(),
                          CreateMockFrame()));
  task_environment_.RunUntilIdle();
}

TEST_P(RTCEncodedVideoStreamTransformerTest, TransformerForwardsFrameToWebRTC) {
  EXPECT_CALL(*webrtc_callback_, OnTransformedFrame);
  encoded_video_stream_transformer_.SendFrameToSink(CreateMockFrame());
  task_environment_.RunUntilIdle();
}

TEST_P(RTCEncodedVideoStreamTransformerTest, IgnoresSsrcForSinglecast) {
  EXPECT_CALL(*webrtc_callback_, OnTransformedFrame);
  std::unique_ptr<webrtc::MockTransformableVideoFrame> mock_frame =
      CreateMockFrame();
  EXPECT_CALL(*mock_frame.get(), GetSsrc)
      .WillRepeatedly(Return(kNonexistentSSRC));
  encoded_video_stream_transformer_.SendFrameToSink(std::move(mock_frame));
  task_environment_.RunUntilIdle();
}

TEST_P(RTCEncodedVideoStreamTransformerTest, ShortCircuitingPropagated) {
  EXPECT_CALL(*webrtc_callback_, StartShortCircuiting);
  encoded_video_stream_transformer_.StartShortCircuiting();
  task_environment_.RunUntilIdle();
}

TEST_P(RTCEncodedVideoStreamTransformerTest,
       ShortCircuitingSetOnLateRegisteredCallback) {
  EXPECT_CALL(*webrtc_callback_, StartShortCircuiting);
  encoded_video_stream_transformer_.StartShortCircuiting();

  rtc::scoped_refptr<MockWebRtcTransformedFrameCallback> webrtc_callback_2(
      new rtc::RefCountedObject<MockWebRtcTransformedFrameCallback>());
  EXPECT_CALL(*webrtc_callback_2, StartShortCircuiting);
  encoded_video_stream_transformer_.RegisterTransformedFrameSinkCallback(
      webrtc_callback_2, kSSRC + 1);
}

TEST_P(RTCEncodedVideoStreamTransformerTest, WaitsForMetronomeTick) {
  if (!GetParam()) {
    return;
  }
  encoded_video_stream_transformer_.SetTransformerCallback(
      WTF::CrossThreadBindRepeating(
          &MockTransformerCallbackHolder::OnEncodedFrame,
          WTF::CrossThreadUnretained(&mock_transformer_callback_holder_)));
  ASSERT_TRUE(encoded_video_stream_transformer_.HasTransformerCallback());

  // There should be no transform call initially.
  EXPECT_CALL(mock_transformer_callback_holder_, OnEncodedFrame).Times(0);
  absl::AnyInvocable<void() &&> callback;
  EXPECT_CALL(*metronome_, RequestCallOnNextTick)
      .WillOnce(
          [&](absl::AnyInvocable<void()&&> c) { callback = std::move(c); });
  const size_t transform_count = 5;
  for (size_t i = 0; i < transform_count; i++) {
    PostCrossThreadTask(
        *webrtc_task_runner_, FROM_HERE,
        CrossThreadBindOnce(&webrtc::FrameTransformerInterface::Transform,
                            encoded_video_stream_transformer_.Delegate(),
                            CreateMockFrame()));
  }
  task_environment_.RunUntilIdle();
  ASSERT_TRUE(callback);

  // But when the metronome ticks, all calls arrive.
  EXPECT_CALL(mock_transformer_callback_holder_, OnEncodedFrame)
      .Times(transform_count);
  // Must be done on the same sequence as the transform calls.
  PostCrossThreadTask(*webrtc_task_runner_, FROM_HERE,
                      CrossThreadBindOnce(
                          [](absl::AnyInvocable<void()&&>* callback) {
                            std::move (*callback)();
                          },
                          CrossThreadUnretained(&callback)));

  task_environment_.RunUntilIdle();
}

TEST_P(RTCEncodedVideoStreamTransformerTest,
       FramesBufferedBeforeShortcircuiting) {
  // Send some frames to be transformed before shortcircuiting.
  const size_t transform_count = 5;
  for (size_t i = 0; i < transform_count; i++) {
    PostCrossThreadTask(
        *webrtc_task_runner_, FROM_HERE,
        CrossThreadBindOnce(&webrtc::FrameTransformerInterface::Transform,
                            encoded_video_stream_transformer_.Delegate(),
                            CreateMockFrame()));
  }

  task_environment_.RunUntilIdle();

  // All frames should be passed back once short circuiting starts.
  EXPECT_CALL(*webrtc_callback_, OnTransformedFrame).Times(transform_count);
  EXPECT_CALL(*webrtc_callback_, StartShortCircuiting);
  encoded_video_stream_transformer_.StartShortCircuiting();

  task_environment_.RunUntilIdle();
}

TEST_P(RTCEncodedVideoStreamTransformerTest,
       FrameArrivingAfterShortcircuitingIsPassedBack) {
  EXPECT_CALL(*webrtc_callback_, StartShortCircuiting);
  encoded_video_stream_transformer_.StartShortCircuiting();

  // Frames passed to Transform after shortcircuting should be passed straight
  // back.
  PostCrossThreadTask(
      *webrtc_task_runner_, FROM_HERE,
      CrossThreadBindOnce(&webrtc::FrameTransformerInterface::Transform,
                          encoded_video_stream_transformer_.Delegate(),
                          CreateMockFrame()));

  EXPECT_CALL(*webrtc_callback_, OnTransformedFrame);
  task_environment_.RunUntilIdle();
}

TEST_P(RTCEncodedVideoStreamTransformerTest,
       FramesBufferedBeforeSettingTransform) {
  // Send some frames to be transformed before a transform is set.
  const size_t transform_count = 5;
  for (size_t i = 0; i < transform_count; i++) {
    PostCrossThreadTask(
        *webrtc_task_runner_, FROM_HERE,
        CrossThreadBindOnce(&webrtc::FrameTransformerInterface::Transform,
                            encoded_video_stream_transformer_.Delegate(),
                            CreateMockFrame()));
  }

  task_environment_.RunUntilIdle();

  // All frames should be passed as soon as a transform callback is provided
  EXPECT_CALL(mock_transformer_callback_holder_, OnEncodedFrame)
      .Times(transform_count);
  encoded_video_stream_transformer_.SetTransformerCallback(
      WTF::CrossThreadBindRepeating(
          &MockTransformerCallbackHolder::OnEncodedFrame,
          WTF::CrossThreadUnretained(&mock_transformer_callback_holder_)));
}

}  // namespace blink
```