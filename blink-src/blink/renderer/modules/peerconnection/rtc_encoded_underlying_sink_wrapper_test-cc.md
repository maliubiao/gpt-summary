Response:
Let's break down the thought process for analyzing the provided C++ test file.

**1. Initial Understanding: Core Purpose**

The file name `rtc_encoded_underlying_sink_wrapper_test.cc` immediately suggests this is a unit test file. The "sink wrapper" part hints at something that sits between a source of data and a destination. The "encoded" part strongly points to handling encoded media data, likely related to WebRTC. The `rtc` prefix reinforces this connection.

**2. Identifying Key Components (Includes and Namespaces)**

The `#include` directives provide crucial context. Scanning them reveals:

* **Testing Frameworks:** `testing/gmock/include/gmock.h` and `testing/gtest/include/gtest/gtest.h` confirm it's a unit test using Google Test and Google Mock.
* **Blink/Chromium Specific:**  Includes like `third_party/blink/renderer/...` indicate this code is part of the Chromium Blink rendering engine. Keywords like `peerconnection`, `rtc_encoded_audio_frame`, `rtc_encoded_video_frame`, `writable_stream` are strong indicators of the functionality being tested.
* **WebRTC Interop:** Includes like `third_party/webrtc/api/...` signify interaction with the underlying WebRTC library.
* **Concurrency/Tasks:** `base/task/single_thread_task_runner.h` suggests handling asynchronous operations within a single thread.
* **Data Handling:** Includes like `base/memory/scoped_refptr.h`, `wtf/vector.h` hint at memory management and data structures.

The `namespace blink {` block confirms the code belongs to the Blink engine.

**3. Focusing on the Class Under Test: `RTCEncodedUnderlyingSinkWrapper`**

The test class name `RTCEncodedUnderlyingSinkWrapperTest` and the frequent instantiation of `RTCEncodedUnderlyingSinkWrapper` are clear signals that this is the central class being tested.

**4. Analyzing Test Cases (Functions Starting with `TEST_F`)**

Each `TEST_F` function represents a specific test scenario. Reading the names gives a good overview of the functionality being tested:

* `WriteToStreamForwardsToWebRtcCallbackAudio/Video`: Tests if writing data through the wrapper triggers the expected WebRTC callback.
* `WriteInvalidDataFailsAudio/Video`: Checks if the wrapper correctly rejects invalid data types.
* `WriteInDifferentDirectionIsAllowedAudio`: Verifies the handling of frame direction.
* `WritingSendFrameSucceedsVideo`/`WritingReceiverFrameSucceedsVideo`:  Specifically tests sending and receiving frame scenarios.
* `WritingBeforeAudioOrVideoIsSetup`/`ClosingBeforeAudioOrVideoIsSetup`/`AbortingBeforeAudioOrVideoIsSetup`:  Tests error handling when the sink isn't properly initialized.
* `RTCEncodedUnderlyingSinkWrapperRestrictionsTest`: This nested test fixture, enabled by a feature flag, focuses on restrictions related to frame ordering and ownership. The test names within this fixture (e.g., `WriteAudioFrameWithSameCounter`, `WriteAudioFrameInDifferentOrder`) reveal tests for specific restriction scenarios.

**5. Understanding the Test Setup (`SetUp` and `TearDown`)**

These methods handle the common setup and cleanup for each test case. In this case, they focus on registering and unregistering callbacks on the `audio_transformer_` and `video_transformer_`.

**6. Identifying Mock Objects and Expectations**

The use of `NiceMock<webrtc::MockTransformableAudioFrame>` and `NiceMock<MockTransformableVideoFrame>` along with `EXPECT_CALL` indicates the use of mocking to isolate the component under test and verify its interactions with dependencies (the WebRTC frame transformers).

**7. Tracing Data Flow**

The tests typically follow a pattern:

1. **Create the sink wrapper:** `CreateSink(script_state)`
2. **Create an underlying sink (audio or video):** `sink->CreateAudioUnderlyingSink(...)` or `sink->CreateVideoUnderlyingSink(...)`
3. **Create a WritableStream:**  This is the interface through which JavaScript would interact with the sink.
4. **Get a writer for the stream:** `stream->getWriter(...)`
5. **Create encoded frame chunks:** `CreateEncodedAudioFrameChunk(...)` or `CreateEncodedVideoFrameChunk(...)` – These simulate the data coming from JavaScript.
6. **Write data to the stream:** `writer->write(...)`
7. **Verify interactions using `EXPECT_CALL`:**  Crucially, checking if `webrtc_callback_->OnTransformedFrame(_)` is called as expected.
8. **Handle stream closure:** `stream->close(...)`
9. **Test error conditions:** Attempting to write after closing, writing invalid data, etc.

**8. Connecting to JavaScript, HTML, and CSS (Based on Context and Keywords)**

Although the test file is C++, the presence of `ScriptState`, `ScriptValue`, and the interaction with `WritableStream` heavily imply a connection to JavaScript.

* **JavaScript Interaction:** The `WritableStream` is a JavaScript API. The test simulates JavaScript code writing encoded frames to this stream. The `RTCEncodedAudioFrame` and `RTCEncodedVideoFrame` objects are also exposed to JavaScript.
* **HTML:**  The PeerConnection API, which these tests are part of, is used in JavaScript within the context of web pages (HTML). Specifically, the `RTCRtpSender` and `RTCRtpReceiver` interfaces use encoded transform functionality.
* **CSS:**  While not directly related at this low level, the overall functionality of WebRTC (and thus encoded transforms) can impact how media is displayed or rendered, which can be styled with CSS. For example, CSS might control the size or positioning of a video element.

**9. Logic Reasoning (Hypothetical Inputs and Outputs)**

For tests like `WriteToStreamForwardsToWebRtcCallbackAudio`, the logic is:

* **Input:** A valid `RTCEncodedAudioFrame` object (represented by the `CreateEncodedAudioFrameChunk` function).
* **Expected Output:** A call to the `webrtc_callback_->OnTransformedFrame` method with the corresponding WebRTC transformable frame.

For error cases like `WriteInvalidDataFailsAudio`:

* **Input:** An invalid data type (e.g., an integer) passed to the `write` method.
* **Expected Output:** An exception being thrown (verified using `DummyExceptionStateForTesting`).

**10. User and Programming Errors**

The tests themselves highlight potential errors:

* **Writing after closing:** The `WriteToStreamForwardsToWebRtcCallbackAudio` test explicitly checks this.
* **Providing invalid data:** The `WriteInvalidDataFailsAudio/Video` tests cover this.
* **Incorrect setup:** The tests `WritingBeforeAudioOrVideoIsSetup`, `ClosingBeforeAudioOrVideoIsSetup`, and `AbortingBeforeAudioOrVideoIsSetup` show errors arising from using the sink before it's initialized.
* **Frame ordering/ownership restrictions:** The `RTCEncodedUnderlyingSinkWrapperRestrictionsTest` suite focuses on errors related to violating the enforced rules.

**11. User Operation and Debugging**

To reach this code during debugging:

1. **User Action:** A user interacts with a web page that uses WebRTC and encoded transforms. This could involve making a video call, sharing a screen, or using a media processing feature that leverages encoded transforms.
2. **JavaScript Execution:** The JavaScript code uses the `RTCRtpSender` or `RTCRtpReceiver` APIs to insert a transform stream. This involves setting the `transform` property of the sender or receiver.
3. **C++ Code Invocation:** When a media frame needs to be processed through the transform, the Blink rendering engine's C++ code comes into play. The `RTCEncodedUnderlyingSinkWrapper` is part of this pipeline, acting as the sink for the transformed frames.
4. **Test Case Simulation:** The unit tests simulate this flow by creating `RTCEncodedAudioFrame`/`RTCEncodedVideoFrame` objects (representing data from JavaScript) and writing them to the sink. The `webrtc_callback_` mocks the next stage in the processing pipeline.

By setting breakpoints in this test file and the related source code (e.g., `RTCEncodedUnderlyingSinkWrapper.cc`, `RTCEncodedAudioStreamTransformer.cc`, `RTCEncodedVideoStreamTransformer.cc`), developers can trace the flow of media data and understand how the encoded transform mechanism works. Failures in these tests often indicate bugs in the underlying implementation of the encoded transform feature.
这个文件 `rtc_encoded_underlying_sink_wrapper_test.cc` 是 Chromium Blink 引擎中用于测试 `RTCEncodedUnderlyingSinkWrapper` 类的单元测试文件。`RTCEncodedUnderlyingSinkWrapper` 的主要功能是 **作为 WebRTC 中可写流（WritableStream）的底层接收器（underlying sink），用于接收经过编码的音频和视频帧数据，并将这些数据传递给底层的 WebRTC 框架进行进一步处理。**

更具体地说，它做了以下几件事情：

1. **接收编码后的媒体帧:**  它作为 JavaScript `WritableStream` 的底层实现，当 JavaScript 代码向这个流写入数据时，`RTCEncodedUnderlyingSinkWrapper` 负责接收这些数据。这些数据通常是 `RTCEncodedAudioFrame` 或 `RTCEncodedVideoFrame` 对象。
2. **桥接 Blink 和 WebRTC:**  它负责将 Blink 的数据结构（`RTCEncodedAudioFrame`, `RTCEncodedVideoFrame`）转换为 WebRTC 期望的格式，并调用 WebRTC 提供的接口将这些帧传递下去。这通常涉及 `webrtc::TransformedFrameCallback`。
3. **管理资源:** 它可能负责一些资源的生命周期管理，例如在流关闭或中止时进行清理。
4. **处理错误:** 它需要处理各种可能发生的错误情况，例如在未正确初始化的情况下尝试写入数据。
5. **施加限制 (基于 Feature Flag):**  在启用了 `kWebRtcRtpScriptTransformerFrameRestrictions` 特性标志时，它会检查接收到的帧的顺序和所有者 ID，以防止某些潜在的安全问题或不当使用。

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 文件直接与 JavaScript 中的 WebRTC API 相关联。

* **JavaScript:**
    * **`RTCRtpSender.transform` 和 `RTCRtpReceiver.transform`:**  JavaScript 代码可以使用 `RTCRtpSender` 或 `RTCRtpReceiver` 的 `transform` 属性来设置一个 `TransformStream`。这个 `TransformStream` 的 writable side (sink)  在 Blink 引擎中就由 `RTCEncodedUnderlyingSinkWrapper` 来实现。
    * **`WritableStream` API:**  JavaScript 代码通过 `WritableStream` API 向 `RTCEncodedUnderlyingSinkWrapper` 写入数据。写入的数据是 `RTCEncodedAudioFrame` 或 `RTCEncodedVideoFrame` 的实例，这些对象也在 JavaScript 中有对应的表示。
    * **`RTCEncodedAudioFrame` 和 `RTCEncodedVideoFrame`:** 这些 JavaScript 对象封装了编码后的音频和视频数据，它们的数据结构和生命周期与 `RTCEncodedUnderlyingSinkWrapper` 处理的 C++ 对象密切相关。

    **举例说明:**

    ```javascript
    const sender = peerConnection.addTrack(videoTrack).sender;
    const transformStream = new TransformStream({
      transform(chunk, controller) {
        // 'chunk' is an RTCEncodedVideoFrame instance here
        console.log("Received encoded video frame in transform:", chunk);
        controller.enqueue(chunk); // Pass it along
      }
    });
    sender.transform = transformStream;
    ```

    在这个例子中，`transformStream.writable` 的底层 sink 就是由 `RTCEncodedUnderlyingSinkWrapper` 实现的。当 WebRTC 捕获到视频帧并经过编码后，这个编码后的帧会被封装成 `RTCEncodedVideoFrame` 对象，然后被写入到 `transformStream.writable`，最终被 `RTCEncodedUnderlyingSinkWrapper` 接收并处理。

* **HTML:**  HTML 文件中包含了使用 WebRTC API 的 JavaScript 代码。例如，`<video>` 标签用于显示接收到的视频流，而相关的 JavaScript 代码会建立 `RTCPeerConnection` 连接，并可能使用 `transform` API 来处理编码后的媒体数据。

* **CSS:** CSS 主要负责控制网页的样式。虽然与 `RTCEncodedUnderlyingSinkWrapper` 的关系不直接，但 CSS 可以影响 `<video>` 标签的显示效果，从而间接地与 WebRTC 功能相关联。

**逻辑推理与假设输入输出:**

假设 JavaScript 代码创建了一个 `TransformStream` 并将其赋值给 `RTCRtpSender.transform`，并且向这个 transform stream 的 writable side 写入了一个 `RTCEncodedAudioFrame` 对象。

* **假设输入:**  一个 JavaScript `RTCEncodedAudioFrame` 对象，包含编码后的音频数据，以及一些元数据（例如时间戳）。
* **处理过程:**
    1. JavaScript 代码调用 `writableStream.getWriter().write(encodedAudioFrame)`。
    2. Blink 引擎接收到这个写操作，并将其传递给 `RTCEncodedUnderlyingSinkWrapper` 的 `write` 方法。
    3. `RTCEncodedUnderlyingSinkWrapper` 将 `RTCEncodedAudioFrame` 对象转换为 WebRTC 期望的 `webrtc::TransformableAudioFrameInterface` 对象。
    4. `RTCEncodedUnderlyingSinkWrapper` 调用已注册的 `webrtc::TransformedFrameCallback` 的 `OnTransformedFrame` 方法，将转换后的 WebRTC 帧传递下去。
* **假设输出:**  WebRTC 框架接收到转换后的音频帧，并进行后续处理（例如网络传输）。

**用户或编程常见的使用错误:**

1. **在底层 sink 未初始化之前写入数据:**  如果 JavaScript 代码在 `transform` 属性被设置之前尝试向与该 transform 关联的 `WritableStream` 写入数据，`RTCEncodedUnderlyingSinkWrapper` 会抛出异常，因为底层的 WebRTC 组件尚未设置好。测试用例 `WritingBeforeAudioOrVideoIsSetup` 就是测试这种情况。

2. **写入无效的数据类型:**  `RTCEncodedUnderlyingSinkWrapper` 期望接收的是 `RTCEncodedAudioFrame` 或 `RTCEncodedVideoFrame` 对象。如果 JavaScript 代码尝试写入其他类型的数据（例如普通的 JavaScript 对象或数字），会导致错误。测试用例 `WriteInvalidDataFailsAudio` 和 `WriteInvalidDataFailsVideo` 就是测试这种情况。

3. **在流关闭后尝试写入数据:** 一旦与 `RTCEncodedUnderlyingSinkWrapper` 关联的 `WritableStream` 被关闭，任何后续的写入操作都会失败。测试用例 `WriteToStreamForwardsToWebRtcCallbackAudio` 和 `WriteToStreamForwardsToWebRtcCallbackVideo` 验证了这一点。

4. **(在启用限制的情况下) 乱序或重复写入帧:** 如果启用了 `kWebRtcRtpScriptTransformerFrameRestrictions` 特性，`RTCEncodedUnderlyingSinkWrapper` 会检查帧的顺序和所有者。写入与之前相同的计数器值的帧或者乱序的帧可能会被拒绝。测试用例 `WriteAudioFrameWithSameCounter` 和 `WriteAudioFrameInDifferentOrder` 等测试了这些限制。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户发起 WebRTC 会话:** 用户在一个网页上点击“发起通话”或“共享屏幕”按钮，触发 JavaScript 代码开始建立 `RTCPeerConnection` 连接。

2. **JavaScript 设置编码变换:**  JavaScript 代码获取 `RTCRtpSender` 或 `RTCRtpReceiver` 对象，并设置其 `transform` 属性为一个 `TransformStream` 实例。

3. **WebRTC 捕获和编码媒体:** 当进行视频通话或屏幕共享时，用户的摄像头或屏幕内容被 WebRTC 引擎捕获，并进行编码（例如使用 VP8, H.264 等编码器）。

4. **编码后的帧传递给 TransformStream:**  WebRTC 引擎将编码后的媒体帧封装成 `RTCEncodedVideoFrame` 或 `RTCEncodedAudioFrame` 对象。

5. **写入 WritableStream:**  这些编码后的帧被写入到 `TransformStream` 的 writable side。这个 writable side 的底层实现就是 `RTCEncodedUnderlyingSinkWrapper`。

6. **C++ 代码处理:**  Blink 引擎的 C++ 代码接收到写入操作，`RTCEncodedUnderlyingSinkWrapper` 的 `write` 方法被调用，开始处理这些编码后的帧。

**调试线索:**

* **在 JavaScript 中设置断点:** 在设置 `transform` 属性的地方，以及 `TransformStream` 的 `transform` 函数中设置断点，可以查看数据流的起始位置。
* **在 `RTCEncodedUnderlyingSinkWrapper::CreateAudioUnderlyingSink` 或 `RTCEncodedUnderlyingSinkWrapper::CreateVideoUnderlyingSink` 设置断点:** 这些方法在创建底层 sink 时被调用，可以确认 sink 是否被正确创建。
* **在 `RTCEncodedUnderlyingSinkWrapper::write` 方法设置断点:**  这是接收编码后帧的关键入口点，可以查看接收到的帧数据和状态。
* **在 `MockWebRtcTransformedFrameCallback::OnTransformedFrame` 设置断点:** 可以验证 `RTCEncodedUnderlyingSinkWrapper` 是否成功将帧传递给了底层的 WebRTC 回调。

通过以上步骤，开发者可以逐步跟踪编码后的媒体数据从 JavaScript 到 Blink 引擎，最终到达 WebRTC 框架的过程，从而定位问题。

Prompt: 
```
这是目录为blink/renderer/modules/peerconnection/rtc_encoded_underlying_sink_wrapper_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_underlying_sink_wrapper.h"

#include "base/memory/scoped_refptr.h"
#include "base/task/single_thread_task_runner.h"
#include "base/unguessable_token.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_encoded_audio_frame.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream_default_writer.h"
#include "third_party/blink/renderer/modules/peerconnection/peer_connection_features.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_audio_frame.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_audio_frame_delegate.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_video_frame.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_video_frame_delegate.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_encoded_audio_stream_transformer.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_encoded_video_stream_transformer.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/webrtc/api/frame_transformer_interface.h"
#include "third_party/webrtc/api/scoped_refptr.h"
#include "third_party/webrtc/api/test/mock_transformable_audio_frame.h"
#include "third_party/webrtc/api/test/mock_transformable_video_frame.h"
#include "third_party/webrtc/rtc_base/ref_counted_object.h"

using testing::_;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;
using webrtc::MockTransformableVideoFrame;

namespace blink {

const uint32_t kSSRC = 1;

namespace {

class MockWebRtcTransformedFrameCallback
    : public webrtc::TransformedFrameCallback {
 public:
  MOCK_METHOD1(OnTransformedFrame,
               void(std::unique_ptr<webrtc::TransformableFrameInterface>));
};

}  // namespace

class RTCEncodedUnderlyingSinkWrapperTest : public testing::Test {
 public:
  RTCEncodedUnderlyingSinkWrapperTest()
      : main_task_runner_(
            blink::scheduler::GetSingleThreadTaskRunnerForTesting()),
        webrtc_callback_(
            new rtc::RefCountedObject<MockWebRtcTransformedFrameCallback>()),
        audio_transformer_(main_task_runner_),
        video_transformer_(main_task_runner_, /*metronome*/ nullptr) {}

  void SetUp() override {
    EXPECT_FALSE(audio_transformer_.HasTransformedFrameCallback());
    audio_transformer_.RegisterTransformedFrameCallback(webrtc_callback_);
    EXPECT_TRUE(audio_transformer_.HasTransformedFrameCallback());
    EXPECT_FALSE(video_transformer_.HasTransformedFrameSinkCallback(kSSRC));
    video_transformer_.RegisterTransformedFrameSinkCallback(webrtc_callback_,
                                                            kSSRC);
    EXPECT_TRUE(video_transformer_.HasTransformedFrameSinkCallback(kSSRC));
  }

  void TearDown() override {
    platform_->RunUntilIdle();
    audio_transformer_.UnregisterTransformedFrameCallback();
    EXPECT_FALSE(audio_transformer_.HasTransformedFrameCallback());
    video_transformer_.UnregisterTransformedFrameSinkCallback(kSSRC);
    EXPECT_FALSE(video_transformer_.HasTransformedFrameSinkCallback(kSSRC));
  }

  RTCEncodedUnderlyingSinkWrapper* CreateSink(ScriptState* script_state) {
    return MakeGarbageCollected<RTCEncodedUnderlyingSinkWrapper>(script_state);
  }

  RTCEncodedAudioStreamTransformer* GetAudioTransformer() {
    return &audio_transformer_;
  }
  RTCEncodedVideoStreamTransformer* GetVideoTransformer() {
    return &video_transformer_;
  }

  RTCEncodedAudioFrame* CreateEncodedAudioFrame(
      ScriptState* script_state,
      base::UnguessableToken owner_id,
      int64_t counter,
      webrtc::TransformableFrameInterface::Direction direction =
          webrtc::TransformableFrameInterface::Direction::kSender,
      size_t payload_length = 100,
      bool expect_data_read = false) {
    auto mock_frame =
        std::make_unique<NiceMock<webrtc::MockTransformableAudioFrame>>();
    ON_CALL(*mock_frame.get(), GetDirection).WillByDefault(Return(direction));
    if (expect_data_read) {
      EXPECT_CALL(*mock_frame.get(), GetData)
          .WillOnce(
              Return(rtc::ArrayView<const uint8_t>(buffer, payload_length)));
    } else {
      EXPECT_CALL(*mock_frame.get(), GetData).Times(0);
    }
    std::unique_ptr<webrtc::TransformableAudioFrameInterface> audio_frame =
        base::WrapUnique(static_cast<webrtc::TransformableAudioFrameInterface*>(
            mock_frame.release()));
    return MakeGarbageCollected<RTCEncodedAudioFrame>(std::move(audio_frame),
                                                      owner_id, counter);
  }

  ScriptValue CreateEncodedAudioFrameChunk(
      ScriptState* script_state,
      base::UnguessableToken owner_id,
      int64_t counter,
      webrtc::TransformableFrameInterface::Direction direction =
          webrtc::TransformableFrameInterface::Direction::kSender) {
    return ScriptValue(
        script_state->GetIsolate(),
        ToV8Traits<RTCEncodedAudioFrame>::ToV8(
            script_state, CreateEncodedAudioFrame(script_state, owner_id,
                                                  counter, direction)));
  }

  ScriptValue CreateEncodedVideoFrameChunk(
      ScriptState* script_state,
      base::UnguessableToken owner_id,
      int64_t counter,
      webrtc::TransformableFrameInterface::Direction direction =
          webrtc::TransformableFrameInterface::Direction::kSender) {
    auto mock_frame = std::make_unique<NiceMock<MockTransformableVideoFrame>>();

    ON_CALL(*mock_frame.get(), GetSsrc).WillByDefault(Return(kSSRC));
    ON_CALL(*mock_frame.get(), GetDirection).WillByDefault(Return(direction));
    RTCEncodedVideoFrame* frame = MakeGarbageCollected<RTCEncodedVideoFrame>(
        std::move(mock_frame), owner_id, counter);
    return ScriptValue(
        script_state->GetIsolate(),
        ToV8Traits<RTCEncodedVideoFrame>::ToV8(script_state, frame));
  }

 protected:
  test::TaskEnvironment task_environment_;
  ScopedTestingPlatformSupport<TestingPlatformSupport> platform_;
  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner_;
  rtc::scoped_refptr<MockWebRtcTransformedFrameCallback> webrtc_callback_;
  RTCEncodedAudioStreamTransformer audio_transformer_;
  RTCEncodedVideoStreamTransformer video_transformer_;
  uint8_t buffer[1500];
};

TEST_F(RTCEncodedUnderlyingSinkWrapperTest,
       WriteToStreamForwardsToWebRtcCallbackAudio) {
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  auto* sink = CreateSink(script_state);
  base::UnguessableToken owner_id = base::UnguessableToken::Create();
  sink->CreateAudioUnderlyingSink(audio_transformer_.GetBroker(), owner_id);
  auto* stream =
      WritableStream::CreateWithCountQueueingStrategy(script_state, sink, 1u);

  NonThrowableExceptionState exception_state;
  auto* writer = stream->getWriter(script_state, exception_state);

  EXPECT_CALL(*webrtc_callback_, OnTransformedFrame(_));
  ScriptPromiseTester write_tester(
      script_state, writer->write(script_state,
                                  CreateEncodedAudioFrameChunk(
                                      script_state, owner_id, /*counter=*/1),
                                  exception_state));
  EXPECT_FALSE(write_tester.IsFulfilled());

  writer->releaseLock(script_state);
  ScriptPromiseTester close_tester(
      script_state, stream->close(script_state, exception_state));
  close_tester.WaitUntilSettled();

  // Writing to the sink after the stream closes should fail.
  DummyExceptionStateForTesting dummy_exception_state;
  sink->write(
      script_state,
      CreateEncodedAudioFrameChunk(script_state, owner_id, /*counter=*/2),
      /*controller=*/nullptr, dummy_exception_state);
  EXPECT_TRUE(dummy_exception_state.HadException());
  EXPECT_EQ(dummy_exception_state.Code(),
            static_cast<ExceptionCode>(DOMExceptionCode::kInvalidStateError));
}

TEST_F(RTCEncodedUnderlyingSinkWrapperTest, WriteInvalidDataFailsAudio) {
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  auto* sink = CreateSink(script_state);
  sink->CreateAudioUnderlyingSink(audio_transformer_.GetBroker(),
                                  base::UnguessableToken::Create());
  ScriptValue v8_integer =
      ScriptValue(script_state->GetIsolate(),
                  v8::Integer::New(script_state->GetIsolate(), 0));

  // Writing something that is not an RTCEncodedAudioFrame integer to the sink
  // should fail.
  DummyExceptionStateForTesting dummy_exception_state;
  sink->write(script_state, v8_integer, /*controller=*/nullptr,
              dummy_exception_state);
  EXPECT_TRUE(dummy_exception_state.HadException());
}

TEST_F(RTCEncodedUnderlyingSinkWrapperTest,
       WriteInDifferentDirectionIsAllowedAudio) {
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  auto* sink = CreateSink(script_state);
  base::UnguessableToken owner_id = base::UnguessableToken::Create();
  sink->CreateAudioUnderlyingSink(audio_transformer_.GetBroker(), owner_id);
  // Write an encoded chunk with direction set to Receiver should work even
  // though it doesn't match the direction of sink creation.
  DummyExceptionStateForTesting dummy_exception_state;
  sink->write(script_state,
              CreateEncodedAudioFrameChunk(
                  script_state, owner_id, /*counter=*/1,
                  webrtc::TransformableFrameInterface::Direction::kReceiver),
              /*controller=*/nullptr, dummy_exception_state);
  EXPECT_FALSE(dummy_exception_state.HadException());
}

TEST_F(RTCEncodedUnderlyingSinkWrapperTest,
       WriteToStreamForwardsToWebRtcCallbackVideo) {
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  auto* sink = CreateSink(script_state);
  base::UnguessableToken owner_id = base::UnguessableToken::Create();
  sink->CreateVideoUnderlyingSink(video_transformer_.GetBroker(), owner_id);
  auto* stream =
      WritableStream::CreateWithCountQueueingStrategy(script_state, sink, 1u);

  NonThrowableExceptionState exception_state;
  auto* writer = stream->getWriter(script_state, exception_state);

  EXPECT_CALL(*webrtc_callback_, OnTransformedFrame(_));
  ScriptPromiseTester write_tester(
      script_state, writer->write(script_state,
                                  CreateEncodedVideoFrameChunk(
                                      script_state, owner_id, /*counter=*/1),
                                  exception_state));
  EXPECT_FALSE(write_tester.IsFulfilled());

  writer->releaseLock(script_state);
  ScriptPromiseTester close_tester(
      script_state, stream->close(script_state, exception_state));
  close_tester.WaitUntilSettled();

  // Writing to the sink after the stream closes should fail.
  DummyExceptionStateForTesting dummy_exception_state;
  sink->write(
      script_state,
      CreateEncodedVideoFrameChunk(script_state, owner_id, /*counter=*/2),
      nullptr, dummy_exception_state);
  EXPECT_TRUE(dummy_exception_state.HadException());
  EXPECT_EQ(dummy_exception_state.Code(),
            static_cast<ExceptionCode>(DOMExceptionCode::kInvalidStateError));
}

TEST_F(RTCEncodedUnderlyingSinkWrapperTest, WriteInvalidDataFailsVideo) {
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  auto* sink = CreateSink(script_state);
  sink->CreateVideoUnderlyingSink(video_transformer_.GetBroker(),
                                  base::UnguessableToken::Create());
  ScriptValue v8_integer =
      ScriptValue(script_state->GetIsolate(),
                  v8::Integer::New(script_state->GetIsolate(), 0));

  // Writing something that is not an RTCEncodedVideoFrame integer to the sink
  // should fail.
  DummyExceptionStateForTesting dummy_exception_state;
  sink->write(script_state, v8_integer, nullptr, dummy_exception_state);
  EXPECT_TRUE(dummy_exception_state.HadException());
}

TEST_F(RTCEncodedUnderlyingSinkWrapperTest, WritingSendFrameSucceedsVideo) {
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  auto* sink = CreateSink(script_state);
  base::UnguessableToken owner_id = base::UnguessableToken::Create();
  sink->CreateVideoUnderlyingSink(video_transformer_.GetBroker(), owner_id);

  EXPECT_CALL(*webrtc_callback_, OnTransformedFrame(_));

  DummyExceptionStateForTesting dummy_exception_state;
  sink->write(script_state,
              CreateEncodedVideoFrameChunk(
                  script_state, owner_id, /*counter=*/1,
                  webrtc::TransformableFrameInterface::Direction::kSender),
              nullptr, dummy_exception_state);
  EXPECT_FALSE(dummy_exception_state.HadException());
}

TEST_F(RTCEncodedUnderlyingSinkWrapperTest, WritingReceiverFrameSucceedsVideo) {
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  auto* sink = CreateSink(script_state);
  base::UnguessableToken owner_id = base::UnguessableToken::Create();
  sink->CreateVideoUnderlyingSink(video_transformer_.GetBroker(), owner_id);

  EXPECT_CALL(*webrtc_callback_, OnTransformedFrame(_));

  DummyExceptionStateForTesting dummy_exception_state;
  sink->write(script_state,
              CreateEncodedVideoFrameChunk(
                  script_state, owner_id, /*counter=*/1,
                  webrtc::TransformableFrameInterface::Direction::kReceiver),
              nullptr, dummy_exception_state);
  EXPECT_FALSE(dummy_exception_state.HadException());
}

TEST_F(RTCEncodedUnderlyingSinkWrapperTest, WritingBeforeAudioOrVideoIsSetup) {
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  auto* sink = CreateSink(script_state);

  DummyExceptionStateForTesting dummy_exception_state;
  sink->write(script_state,
              CreateEncodedVideoFrameChunk(
                  script_state, base::UnguessableToken::Null(), /*counter=*/1,
                  webrtc::TransformableFrameInterface::Direction::kReceiver),
              nullptr, dummy_exception_state);
  EXPECT_TRUE(dummy_exception_state.HadException());
}

TEST_F(RTCEncodedUnderlyingSinkWrapperTest, ClosingBeforeAudioOrVideoIsSetup) {
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  auto* sink = CreateSink(script_state);

  DummyExceptionStateForTesting dummy_exception_state;
  sink->close(script_state, dummy_exception_state);
  EXPECT_TRUE(dummy_exception_state.HadException());
}

TEST_F(RTCEncodedUnderlyingSinkWrapperTest, AbortingBeforeAudioOrVideoIsSetup) {
  V8TestingScope v8_scope;
  ScriptState* script_state = v8_scope.GetScriptState();
  auto* sink = CreateSink(script_state);

  DummyExceptionStateForTesting dummy_exception_state;
  sink->abort(script_state, ScriptValue(), dummy_exception_state);
  EXPECT_TRUE(dummy_exception_state.HadException());
}

class RTCEncodedUnderlyingSinkWrapperRestrictionsTest
    : public RTCEncodedUnderlyingSinkWrapperTest {
 public:
  RTCEncodedUnderlyingSinkWrapperRestrictionsTest() {
    scoped_feature_list_.InitAndEnableFeature(
        blink::kWebRtcRtpScriptTransformerFrameRestrictions);
  }

  void WriteTwoFrames(ScriptState* script_state,
                      String kind,
                      int64_t counter_frame1,
                      int64_t counter_frame2) {
    auto* sink = CreateSink(script_state);
    base::UnguessableToken owner_id = base::UnguessableToken::Create();
    if (kind == "audio") {
      sink->CreateAudioUnderlyingSink(audio_transformer_.GetBroker(), owner_id);
    } else {
      CHECK_EQ(kind, "video");
      sink->CreateVideoUnderlyingSink(video_transformer_.GetBroker(), owner_id);
    }
    auto* stream =
        WritableStream::CreateWithCountQueueingStrategy(script_state, sink, 1u);

    NonThrowableExceptionState exception_state;
    auto* writer = stream->getWriter(script_state, exception_state);

    EXPECT_CALL(*webrtc_callback_, OnTransformedFrame(_));
    ScriptValue encoded_frame1;
    if (kind == "audio") {
      encoded_frame1 =
          CreateEncodedAudioFrameChunk(script_state, owner_id, counter_frame1);
    } else {
      CHECK_EQ(kind, "video");
      encoded_frame1 =
          CreateEncodedVideoFrameChunk(script_state, owner_id, counter_frame1);
    }
    ScriptPromiseTester write_tester(
        script_state,
        writer->write(script_state, encoded_frame1, exception_state));
    write_tester.WaitUntilSettled();
    EXPECT_TRUE(write_tester.IsFulfilled());

    EXPECT_CALL(*webrtc_callback_, OnTransformedFrame(_)).Times(0);
    ScriptValue encoded_frame2;
    if (kind == "audio") {
      encoded_frame2 =
          CreateEncodedAudioFrameChunk(script_state, owner_id, counter_frame2);
    } else {
      CHECK_EQ(kind, "video");
      encoded_frame2 =
          CreateEncodedVideoFrameChunk(script_state, owner_id, counter_frame2);
    }
    ScriptPromiseTester write_tester2(
        script_state,
        writer->write(script_state, encoded_frame2, exception_state));
    write_tester2.WaitUntilSettled();
    EXPECT_TRUE(write_tester2.IsFulfilled());

    writer->releaseLock(script_state);
    ScriptPromiseTester close_tester(
        script_state, stream->close(script_state, exception_state));
    close_tester.WaitUntilSettled();
    EXPECT_TRUE(close_tester.IsFulfilled());
  }

  void WriteFrame(ScriptState* script_state, String kind) {
    auto* sink = CreateSink(script_state);
    if (kind == "audio") {
      sink->CreateAudioUnderlyingSink(audio_transformer_.GetBroker(),
                                      base::UnguessableToken::Create());
    } else {
      CHECK_EQ(kind, "video");
      sink->CreateVideoUnderlyingSink(video_transformer_.GetBroker(),
                                      base::UnguessableToken::Create());
    }
    auto* stream =
        WritableStream::CreateWithCountQueueingStrategy(script_state, sink, 1u);

    NonThrowableExceptionState exception_state;
    auto* writer = stream->getWriter(script_state, exception_state);

    EXPECT_CALL(*webrtc_callback_, OnTransformedFrame(_)).Times(0);
    ScriptValue encoded_frame;
    if (kind == "audio") {
      encoded_frame = CreateEncodedAudioFrameChunk(
          script_state, base::UnguessableToken::Create(), /*counter=*/1);
    } else {
      encoded_frame = CreateEncodedVideoFrameChunk(
          script_state, base::UnguessableToken::Create(), /*counter=*/1);
    }
    ScriptPromiseTester write_tester(
        script_state,
        writer->write(script_state, encoded_frame, exception_state));
    write_tester.WaitUntilSettled();
    EXPECT_TRUE(write_tester.IsFulfilled());

    writer->releaseLock(script_state);
    ScriptPromiseTester close_tester(
        script_state, stream->close(script_state, exception_state));
    close_tester.WaitUntilSettled();
    EXPECT_TRUE(close_tester.IsFulfilled());
  }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
};

TEST_F(RTCEncodedUnderlyingSinkWrapperRestrictionsTest,
       WriteAudioFrameWithSameCounter) {
  SCOPED_TRACE("WriteAudioFrameWithSameCounter");
  WriteTwoFrames(V8TestingScope().GetScriptState(), "audio",
                 /*counter_frame1=*/1, /*counter_frame2=*/1);
}

TEST_F(RTCEncodedUnderlyingSinkWrapperRestrictionsTest,
       WriteAudioFrameInDifferentOrder) {
  SCOPED_TRACE("WriteAudioFrameInDifferentOrder");
  WriteTwoFrames(V8TestingScope().GetScriptState(), "audio",
                 /*counter_frame1=*/2, /*counter_frame2=*/1);
}

TEST_F(RTCEncodedUnderlyingSinkWrapperRestrictionsTest,
       WriteVideoFrameWithSameCounter) {
  SCOPED_TRACE("WriteVideoFrameWithSameCounter");
  WriteTwoFrames(V8TestingScope().GetScriptState(), "video",
                 /*counter_frame1=*/1, /*counter_frame2=*/1);
}

TEST_F(RTCEncodedUnderlyingSinkWrapperRestrictionsTest,
       WriteVideoFrameInDifferentOrder) {
  SCOPED_TRACE("WriteVideoFrameInDifferentOrder");
  WriteTwoFrames(V8TestingScope().GetScriptState(), "video",
                 /*counter_frame1=*/2, /*counter_frame2=*/1);
}

TEST_F(RTCEncodedUnderlyingSinkWrapperRestrictionsTest,
       WriteAudioFrameWithDifferentOwnerId) {
  SCOPED_TRACE("WriteAudioFrameWithDifferentOwnerId");
  WriteFrame(V8TestingScope().GetScriptState(), "audio");
}

TEST_F(RTCEncodedUnderlyingSinkWrapperRestrictionsTest,
       WriteVideoFrameWithDifferentOwnerId) {
  SCOPED_TRACE("WriteVideoFrameWithDifferentOwnerId");
  WriteFrame(V8TestingScope().GetScriptState(), "video");
}

}  // namespace blink

"""

```