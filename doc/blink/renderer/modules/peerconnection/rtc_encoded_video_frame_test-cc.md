Response:
My thought process for analyzing the `rtc_encoded_video_frame_test.cc` file goes through these stages:

1. **Understand the Purpose:** The filename itself (`rtc_encoded_video_frame_test.cc`) strongly suggests this file contains unit tests for the `RTCEncodedVideoFrame` class. The `_test.cc` suffix is a common convention for test files.

2. **Identify Key Classes and Concepts:** I scan the includes and the test structure. Key elements jump out:
    * `RTCEncodedVideoFrame`: The central class being tested.
    * `RTCEncodedVideoFrameMetadata`:  Likely holds metadata associated with the encoded video frame.
    * `RTCEncodedVideoFrameOptions`:  Probably used for constructing or manipulating `RTCEncodedVideoFrame` objects.
    * `MockTransformableVideoFrame`: A mock object from the testing framework (likely `gmock`) used to simulate the underlying WebRTC video frame. This tells me the `RTCEncodedVideoFrame` wraps or interacts with a WebRTC concept.
    * `V8TestingScope`: Indicates interaction with the V8 JavaScript engine.
    * `DummyExceptionStateForTesting`: A testing utility for handling exceptions.
    * WebRTC namespaces and specific metadata classes like `RTPVideoHeaderVP8`, `RTPVideoHeaderVP9`, and `VideoFrameMetadata`. This confirms the WebRTC connection.

3. **Analyze Test Cases:** I go through each `TEST_F` function to understand what specific aspects of `RTCEncodedVideoFrame` are being tested. I look for patterns and common themes. Key observations:
    * **Metadata Handling:**  Many tests focus on getting, setting, and manipulating metadata (`GetMetadataReturnsMetadata`, `SetMetadataPreservesVP9CodecSpecifics`, `SetMetadataMissingFieldsFails`, etc.). This is clearly a core functionality.
    * **Constructor Behavior:** Several tests examine how `RTCEncodedVideoFrame` objects are created, including variations with and without metadata, and copying existing frames (`ConstructorPreservesVP9CodecSpecifics`, `ConstructorMissingFieldsFails`, `ConstructorCopiesMetadata`, etc.).
    * **Error Handling:** Tests like `SetMetadataMissingFieldsFails`, `SetMetadataOnEmptyFrameFails`, and various constructor tests with `DummyExceptionStateForTesting` highlight how the class handles invalid input or states.
    * **Feature Flags:** The use of `ScopedFeatureList` and tests like `SetMetadataWithoutFeatureFailsModifications` and `SetMetadataWithFeatureAllowsModifications` indicates that certain behaviors are controlled by feature flags, a common practice in Chromium.
    * **Empty Frame Handling:** Tests involving `PassWebRtcFrame` and "empty" frames reveal how the class deals with scenarios where the underlying WebRTC frame might be moved or become unavailable.
    * **JavaScript Interaction:** The presence of `V8TestingScope` and the interaction with `DOMArrayBuffer` in tests like `ReadingDataOnEmptyFrameGivesDetachedFrame` suggest that this class is exposed to JavaScript.

4. **Identify Relationships with Web Technologies:** Based on the keywords and concepts identified, I can deduce the connections to JavaScript, HTML, and CSS:
    * **JavaScript:** The `RTCEncodedVideoFrame` is likely exposed as a JavaScript object in the WebRTC API. Methods like `getMetadata()` and `setMetadata()` would correspond to JavaScript methods on this object. The interaction with `DOMArrayBuffer` suggests that the encoded video data itself might be accessed as an `ArrayBuffer` in JavaScript.
    * **HTML:**  While not directly manipulating HTML elements, the `RTCEncodedVideoFrame` plays a crucial role in the `<video>` element's ability to display video streams received through WebRTC.
    * **CSS:** CSS doesn't directly interact with the internals of the `RTCEncodedVideoFrame`, but it controls the presentation and layout of the `<video>` element that displays the decoded video.

5. **Infer User and Programming Errors:** By examining the error handling tests, I can identify common mistakes users or developers might make:
    * Providing incomplete or incorrect metadata.
    * Attempting to modify metadata after the underlying WebRTC frame has been moved.
    * Providing invalid dependencies between frames.
    * Trying to create a new frame from an already empty frame while providing metadata.

6. **Trace User Operations:** I consider how a user interacting with a web page could indirectly trigger the code being tested. This involves understanding the WebRTC API flow:
    * A user grants camera/microphone access.
    * A `RTCPeerConnection` is established.
    * Video frames are captured from the camera.
    * These frames are encoded (this is where `RTCEncodedVideoFrame` comes into play).
    * The encoded frames are sent over the network.
    * On the receiving end, the process is reversed.
    * The tests simulate the manipulation of these *encoded* video frames, particularly focusing on metadata.

7. **Structure the Explanation:** Finally, I organize my findings into the requested categories (functionality, relationship to web technologies, logical reasoning, usage errors, debugging). I use clear and concise language, providing examples where appropriate. I pay attention to the specific constraints of the prompt, like providing assumptions for logical reasoning.
这个文件 `blink/renderer/modules/peerconnection/rtc_encoded_video_frame_test.cc` 是 Chromium Blink 引擎中用于测试 `RTCEncodedVideoFrame` 类的单元测试文件。`RTCEncodedVideoFrame` 类在 WebRTC (Web Real-Time Communication) 的 PeerConnection 模块中扮演着重要的角色，它代表了一个编码后的视频帧。

以下是该文件的功能及其与其他 Web 技术的关系、逻辑推理、常见错误和调试线索：

**功能:**

1. **测试 `RTCEncodedVideoFrame` 类的功能:**  这个文件包含了多个测试用例 (以 `TEST_F` 开头)，用于验证 `RTCEncodedVideoFrame` 类的各种方法和行为是否符合预期。
2. **测试元数据 (Metadata) 的获取和设置:** 许多测试用例关注 `RTCEncodedVideoFrame` 对象关联的元数据 (`RTCEncodedVideoFrameMetadata`) 的获取 (`getMetadata`) 和设置 (`setMetadata`) 功能。这些元数据描述了视频帧的属性，例如帧 ID、时间戳、编解码器特定信息等。
3. **测试构造函数:**  测试用例验证了创建 `RTCEncodedVideoFrame` 对象的不同方式，包括从现有的帧创建新帧，以及使用 `RTCEncodedVideoFrameOptions` 指定元数据。
4. **模拟 WebRTC 内部行为:**  通过使用 `MockTransformableVideoFrame`，测试模拟了 WebRTC 内部处理视频帧的流程，允许在隔离的环境中测试 `RTCEncodedVideoFrame` 的行为。
5. **验证异常处理:** 测试用例检查了在无效操作或参数下，`RTCEncodedVideoFrame` 是否会抛出预期的异常。
6. **测试特性开关的影响:**  通过 `ScopedFeatureList`，测试了某些功能（例如允许修改所有元数据字段）在启用和禁用状态下的行为差异。

**与 JavaScript, HTML, CSS 的关系:**

`RTCEncodedVideoFrame` 类本身是 Blink 渲染引擎的 C++ 代码，不直接与 JavaScript、HTML 或 CSS 交互。然而，它在 WebRTC API 的实现中扮演着关键角色，而 WebRTC API 是 JavaScript 提供给 Web 开发者的接口，用于实现实时音视频通信。

* **JavaScript:**
    * **WebRTC API:**  开发者可以使用 JavaScript 的 WebRTC API（例如 `RTCRtpSender.replaceTrack()` 中的 `transform` API）来访问和操作编码后的视频帧。`RTCEncodedVideoFrame` 在内部表示这些帧。
    * **`EncodedVideoFrame` 接口:**  JavaScript 中的 `EncodedVideoFrame` 接口是 `RTCEncodedVideoFrame` 在 JavaScript 端的表示。这个测试文件中的功能，最终会影响到 JavaScript 中 `EncodedVideoFrame` 对象的行为和属性。
    * **例子:**  在 JavaScript 中，你可以通过 `RTCRtpSender` 的 `transform` 回调接收到 `EncodedVideoFrame` 对象，并可以访问其 `metadata` 属性。这个测试文件确保了当你在 JavaScript 中访问 `encodedVideoFrame.metadata` 时，能获取到正确的元数据信息，例如 `frameId`、`timestamp` 等。

* **HTML:**
    * **`<video>` 元素:**  WebRTC 捕获或接收到的视频流最终会被渲染到 HTML 的 `<video>` 元素上。`RTCEncodedVideoFrame` 是视频流处理过程中的一个环节，确保了视频帧能够被正确解码和显示。

* **CSS:**
    * **`<video>` 元素样式:** CSS 用于控制 `<video>` 元素的样式和布局，但它不直接操作或感知 `RTCEncodedVideoFrame`。

**逻辑推理 (假设输入与输出):**

假设有以下测试用例：

```c++
TEST_F(RTCEncodedVideoFrameTest, GetFrameId) {
  V8TestingScope v8_scope;
  std::unique_ptr<MockTransformableVideoFrame> frame =
      std::make_unique<MockTransformableVideoFrame>();
  webrtc::VideoFrameMetadata webrtc_metadata;
  webrtc_metadata.SetFrameId(123);
  ON_CALL(*frame, Metadata()).WillByDefault(Return(webrtc_metadata));

  RTCEncodedVideoFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedVideoFrame>(std::move(frame));

  EXPECT_EQ(encoded_frame->getMetadata()->frameId(), 123);
}
```

* **假设输入:** 创建一个 `RTCEncodedVideoFrame` 对象，其底层的 `MockTransformableVideoFrame` 模拟了一个帧 ID 为 123 的 WebRTC 视频帧。
* **预期输出:** 调用 `encoded_frame->getMetadata()->frameId()` 应该返回 123。

**涉及用户或者编程常见的使用错误 (举例说明):**

1. **尝试在 `setMetadata` 中设置缺失必要的字段:**
   * **错误:** 用户可能尝试创建一个新的 `RTCEncodedVideoFrameMetadata` 对象，并只设置部分字段，然后尝试通过 `setMetadata` 应用到现有的 `RTCEncodedVideoFrame`。
   * **代码示例 (模拟用户错误):**
     ```javascript
     // JavaScript (模拟用户行为)
     const sender = peerConnection.addTrack(videoTrack);
     const encoder = sender.createEncodedVideoFrameTransform();
     encoder.ondata = (chunk, controller) => {
       const metadata = chunk.metadata;
       const newMetadata = {}; // 缺少必要的字段
       chunk.setMetadata(newMetadata); // 这在底层可能会导致错误
       controller.enqueue(chunk);
     };
     ```
   * **测试用例覆盖:**  `SetMetadataMissingFieldsFails` 测试用例就覆盖了这种情况，确保当新的元数据缺少必要字段时，`setMetadata` 会抛出异常。

2. **在不允许修改所有字段的情况下尝试修改所有元数据字段:**
   * **错误:** 在某些情况下（可能由特性开关控制），并非所有元数据字段都允许修改。用户可能错误地尝试修改这些受限字段。
   * **测试用例覆盖:** `SetMetadataWithoutFeatureFailsModifications` 和 `SetMetadataWithFeatureAllowsModifications` 测试用例验证了在不同特性开关状态下 `setMetadata` 的行为。

3. **在帧已经为空的情况下尝试设置元数据:**
   * **错误:**  当一个 `RTCEncodedVideoFrame` 的底层 WebRTC 帧被移走（例如，通过 insertable streams 发送）后，它就变成了一个“空”帧。此时再尝试设置元数据可能会导致错误。
   * **测试用例覆盖:** `SetMetadataOnEmptyFrameFails` 测试用例模拟了这种情况。

4. **提供无效的帧依赖关系:**
   * **错误:** 在设置元数据时，提供的帧依赖关系（例如 `dependencies` 字段）可能不符合规范，比如依赖的帧 ID 大于当前帧 ID，或者依赖关系列表过长。
   * **测试用例覆盖:** `SetMetadataRejectsInvalidDependencies` 和 `SetMetadataRejectsTooManyDependencies` 测试用例检查了这些错误情况。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

假设开发者在调试一个 WebRTC 应用，并且怀疑在 `EncodedVideoFrame` 的元数据处理上存在问题。以下是用户操作如何一步步地触发到 `rtc_encoded_video_frame_test.cc` 中测试的代码逻辑的：

1. **用户启动 WebRTC 应用:** 用户打开一个包含 WebRTC 功能的网页应用。
2. **应用请求媒体权限:** JavaScript 代码会请求用户的摄像头和麦克风权限。
3. **建立 `RTCPeerConnection`:**  应用通过 JavaScript 创建 `RTCPeerConnection` 对象，用于建立与其他用户的连接。
4. **添加媒体流到 `RTCPeerConnection`:**  使用 `addTrack()` 方法将本地视频轨道添加到连接中。
5. **使用 Insertable Streams (Encoded Transforms) API (如果使用):**
   * **开发者定义 `transform` 函数:** 开发者可能会使用 `RTCRtpSender.transform` API 来拦截和处理编码后的视频帧。
   * **`transform` 函数接收 `EncodedVideoFrame`:** 当视频帧被编码后，浏览器的 WebRTC 实现会将编码后的帧包装成一个 `EncodedVideoFrame` 对象，并传递给开发者定义的 `transform` 函数。
   * **`EncodedVideoFrame` 内部表示:** 在 Blink 渲染引擎的 C++ 代码中，这个 JavaScript 的 `EncodedVideoFrame` 对象会对应一个 `RTCEncodedVideoFrame` 对象。
6. **开发者尝试操作 `EncodedVideoFrame` 的元数据:**  在 JavaScript 的 `transform` 函数中，开发者可能会尝试读取或修改 `EncodedVideoFrame` 的 `metadata` 属性，或者调用 `setMetadata` 方法。

**调试线索:**

* **断点:** 如果开发者怀疑 `setMetadata` 功能有问题，可以在 `blink/renderer/modules/peerconnection/rtc_encoded_video_frame.cc` 文件的 `setMetadata` 方法处设置断点。当 JavaScript 代码调用 `encodedVideoFrame.setMetadata()` 时，断点会被触发，开发者可以检查 C++ 代码中的变量和执行流程。
* **日志:** 在 C++ 代码中添加日志输出，可以帮助追踪 `RTCEncodedVideoFrame` 对象的生命周期和状态变化，以及元数据的设置过程。
* **测试用例:**  `rtc_encoded_video_frame_test.cc` 中的测试用例可以作为参考，帮助开发者理解 `RTCEncodedVideoFrame` 的预期行为，并编写更精确的测试来复现和解决问题。如果开发者发现一个 bug，可以先编写一个新的测试用例来重现这个 bug，然后在修复代码后运行测试，确保 bug 被修复。
* **检查 WebRTC 内部状态:** 使用 `chrome://webrtc-internals/` 可以查看 WebRTC 的内部状态，包括连接信息、统计数据和事件日志，这有助于了解视频帧的传输和处理过程。

总而言之，`rtc_encoded_video_frame_test.cc` 是一个基础但至关重要的测试文件，它确保了 Blink 引擎中 `RTCEncodedVideoFrame` 类的正确性和稳定性，从而保证了 WebRTC 视频通信功能的可靠运行。虽然开发者通常不会直接接触到这个 C++ 文件，但其测试的逻辑直接影响着 JavaScript WebRTC API 的行为。

### 提示词
```
这是目录为blink/renderer/modules/peerconnection/rtc_encoded_video_frame_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_video_frame.h"

#include "base/test/scoped_feature_list.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_codec_specifics_vp_8.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_encoded_video_frame_metadata.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_encoded_video_frame_options.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_video_frame_delegate.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/webrtc/api/test/mock_transformable_video_frame.h"

using testing::_;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;
using testing::SaveArg;

using webrtc::MockTransformableVideoFrame;

namespace blink {

class RTCEncodedVideoFrameTest : public testing::Test {
  test::TaskEnvironment task_environment_;
};

webrtc::VideoFrameMetadata MockVP9Metadata(MockTransformableVideoFrame* frame) {
  webrtc::VideoFrameMetadata webrtc_metadata;
  std::vector<webrtc::DecodeTargetIndication> decode_target_indications;
  decode_target_indications.push_back(
      webrtc::DecodeTargetIndication::kRequired);
  webrtc_metadata.SetDecodeTargetIndications(decode_target_indications);
  webrtc_metadata.SetIsLastFrameInPicture(true);
  webrtc_metadata.SetSimulcastIdx(5);
  webrtc_metadata.SetFrameType(webrtc::VideoFrameType::kVideoFrameKey);
  webrtc_metadata.SetCodec(webrtc::VideoCodecType::kVideoCodecVP9);
  webrtc_metadata.SetFrameId(1);
  webrtc::RTPVideoHeaderVP9 webrtc_vp9_specifics;
  webrtc_vp9_specifics.InitRTPVideoHeaderVP9();
  webrtc_vp9_specifics.inter_pic_predicted = true;
  webrtc_vp9_specifics.flexible_mode = true;
  webrtc_vp9_specifics.beginning_of_frame = true;
  webrtc_metadata.SetRTPVideoHeaderCodecSpecifics(webrtc_vp9_specifics);

  ON_CALL(*frame, Metadata()).WillByDefault(Return(webrtc_metadata));

  return webrtc_metadata;
}

webrtc::VideoFrameMetadata MockVP8Metadata(MockTransformableVideoFrame* frame) {
  webrtc::VideoFrameMetadata webrtc_metadata;
  webrtc_metadata.SetFrameId(2);
  webrtc_metadata.SetFrameDependencies(std::vector<int64_t>{1});
  webrtc_metadata.SetWidth(800);
  webrtc_metadata.SetHeight(600);
  webrtc_metadata.SetSpatialIndex(3);
  webrtc_metadata.SetTemporalIndex(4);
  std::vector<webrtc::DecodeTargetIndication> decode_target_indications;
  decode_target_indications.push_back(
      webrtc::DecodeTargetIndication::kRequired);
  webrtc_metadata.SetDecodeTargetIndications(decode_target_indications);
  webrtc_metadata.SetIsLastFrameInPicture(true);
  webrtc_metadata.SetSimulcastIdx(5);
  webrtc_metadata.SetFrameType(webrtc::VideoFrameType::kVideoFrameKey);
  webrtc_metadata.SetCodec(webrtc::VideoCodecType::kVideoCodecVP8);
  webrtc_metadata.SetCsrcs({6});
  webrtc_metadata.SetSsrc(7);

  webrtc::RTPVideoHeaderVP8 webrtc_vp8_specifics;
  webrtc_vp8_specifics.nonReference = true;
  webrtc_vp8_specifics.pictureId = 8;
  webrtc_vp8_specifics.tl0PicIdx = 9;
  webrtc_vp8_specifics.temporalIdx = 10;
  webrtc_vp8_specifics.layerSync = true;
  webrtc_vp8_specifics.keyIdx = 11;
  webrtc_vp8_specifics.partitionId = 12;
  webrtc_vp8_specifics.beginningOfPartition = true;
  webrtc_metadata.SetRTPVideoHeaderCodecSpecifics(webrtc_vp8_specifics);

  ON_CALL(*frame, Metadata()).WillByDefault(Return(webrtc_metadata));
  ON_CALL(*frame, GetSsrc()).WillByDefault(Return(7));

  return webrtc_metadata;
}

TEST_F(RTCEncodedVideoFrameTest, GetMetadataReturnsMetadata) {
  V8TestingScope v8_scope;

  std::unique_ptr<MockTransformableVideoFrame> frame =
      std::make_unique<MockTransformableVideoFrame>();

  webrtc::VideoFrameMetadata webrtc_metadata = MockVP8Metadata(frame.get());

  EXPECT_CALL(*frame, Metadata()).WillOnce(Return(webrtc_metadata));
  EXPECT_CALL(*frame, GetPayloadType()).WillRepeatedly(Return(13));
  EXPECT_CALL(*frame, GetTimestamp()).WillRepeatedly(Return(17));

  RTCEncodedVideoFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedVideoFrame>(std::move(frame));

  RTCEncodedVideoFrameMetadata* retrieved_metadata =
      encoded_frame->getMetadata();
  EXPECT_EQ(7u, retrieved_metadata->synchronizationSource());
  EXPECT_EQ(13, retrieved_metadata->payloadType());
  EXPECT_EQ(2, retrieved_metadata->frameId());
  ASSERT_EQ(1u, retrieved_metadata->dependencies().size());
  EXPECT_EQ(1, retrieved_metadata->dependencies()[0]);
  EXPECT_EQ(800, retrieved_metadata->width());
  EXPECT_EQ(600, retrieved_metadata->height());
  EXPECT_EQ(3, retrieved_metadata->spatialIndex());
  EXPECT_EQ(4, retrieved_metadata->temporalIndex());
  ASSERT_EQ(1u, retrieved_metadata->contributingSources().size());
  EXPECT_EQ(6u, retrieved_metadata->contributingSources()[0]);
  EXPECT_EQ(17u, retrieved_metadata->rtpTimestamp());
}

TEST_F(RTCEncodedVideoFrameTest, SetMetadataPreservesVP9CodecSpecifics) {
  V8TestingScope v8_scope;

  std::unique_ptr<MockTransformableVideoFrame> frame =
      std::make_unique<NiceMock<MockTransformableVideoFrame>>();
  webrtc::VideoFrameMetadata webrtc_metadata = MockVP9Metadata(frame.get());

  webrtc::VideoFrameMetadata actual_metadata;
  EXPECT_CALL(*frame, SetMetadata(_)).WillOnce(SaveArg<0>(&actual_metadata));

  RTCEncodedVideoFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedVideoFrame>(std::move(frame));
  DummyExceptionStateForTesting exception_state;

  encoded_frame->setMetadata(encoded_frame->getMetadata(), exception_state);
  EXPECT_FALSE(exception_state.HadException()) << exception_state.Message();

  EXPECT_EQ(actual_metadata.GetFrameId(), webrtc_metadata.GetFrameId());
  EXPECT_EQ(actual_metadata.GetRTPVideoHeaderCodecSpecifics(),
            webrtc_metadata.GetRTPVideoHeaderCodecSpecifics());
}

TEST_F(RTCEncodedVideoFrameTest, SetMetadataMissingFieldsFails) {
  V8TestingScope v8_scope;
  base::test::ScopedFeatureList feature_list_;
  feature_list_.InitWithFeatures(
      /*enabled_features=*/{kAllowRTCEncodedVideoFrameSetMetadataAllFields},
      /*disabled_features=*/{});

  std::unique_ptr<MockTransformableVideoFrame> frame =
      std::make_unique<NiceMock<MockTransformableVideoFrame>>();
  MockVP8Metadata(frame.get());

  RTCEncodedVideoFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedVideoFrame>(std::move(frame));

  RTCEncodedVideoFrameMetadata* empty_metadata =
      RTCEncodedVideoFrameMetadata::Create();

  DummyExceptionStateForTesting exception_state;
  encoded_frame->setMetadata(empty_metadata, exception_state);
  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(exception_state.Message(),
            "Cannot setMetadata: new metadata has member(s) missing.");
}

RTCEncodedVideoFrameMetadata* CreateMetadata(bool change_all_fields = false) {
  RTCEncodedVideoFrameMetadata* new_metadata =
      RTCEncodedVideoFrameMetadata::Create();
  new_metadata->setFrameId(5);
  new_metadata->setDependencies({2, 3, 4});
  new_metadata->setRtpTimestamp(1);
  if (change_all_fields) {
    new_metadata->setWidth(6);
    new_metadata->setHeight(7);
    new_metadata->setSpatialIndex(8);
    new_metadata->setTemporalIndex(9);
    new_metadata->setSynchronizationSource(10);
    new_metadata->setContributingSources({11, 12, 13});
    new_metadata->setPayloadType(14);
  } else {
    new_metadata->setWidth(800);
    new_metadata->setHeight(600);
    new_metadata->setSpatialIndex(3);
    new_metadata->setTemporalIndex(4);
    new_metadata->setSynchronizationSource(7);
    new_metadata->setContributingSources({6});
    new_metadata->setPayloadType(1);
  }
  return new_metadata;
}

TEST_F(RTCEncodedVideoFrameTest, SetMetadataWithoutFeatureFailsModifications) {
  V8TestingScope v8_scope;
  base::test::ScopedFeatureList feature_list_;
  feature_list_.InitWithFeatures(
      /*enabled_features=*/{},
      /*disabled_features=*/{kAllowRTCEncodedVideoFrameSetMetadataAllFields});

  std::unique_ptr<MockTransformableVideoFrame> frame =
      std::make_unique<NiceMock<MockTransformableVideoFrame>>();
  MockVP8Metadata(frame.get());
  EXPECT_CALL(*frame, GetPayloadType()).WillRepeatedly(Return(1));

  webrtc::VideoFrameMetadata actual_metadata;
  EXPECT_CALL(*frame, SetMetadata(_)).Times(0);

  RTCEncodedVideoFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedVideoFrame>(std::move(frame));

  RTCEncodedVideoFrameMetadata* new_metadata =
      CreateMetadata(/*change_all_fields=*/true);

  DummyExceptionStateForTesting exception_state;
  encoded_frame->setMetadata(new_metadata, exception_state);
  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(exception_state.Message(),
            "Cannot setMetadata: invalid modification of "
            "RTCEncodedVideoFrameMetadata.");
}

TEST_F(RTCEncodedVideoFrameTest, SetMetadataWithFeatureAllowsModifications) {
  V8TestingScope v8_scope;
  base::test::ScopedFeatureList feature_list_;
  feature_list_.InitWithFeatures(
      /*enabled_features=*/{kAllowRTCEncodedVideoFrameSetMetadataAllFields},
      /*disabled_features=*/{});

  std::unique_ptr<MockTransformableVideoFrame> frame =
      std::make_unique<NiceMock<MockTransformableVideoFrame>>();
  MockVP8Metadata(frame.get());

  webrtc::VideoFrameMetadata actual_metadata;
  EXPECT_CALL(*frame, SetMetadata(_)).WillOnce(SaveArg<0>(&actual_metadata));
  EXPECT_CALL(*frame, GetPayloadType()).WillRepeatedly(Return(14));

  RTCEncodedVideoFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedVideoFrame>(std::move(frame));

  RTCEncodedVideoFrameMetadata* new_metadata =
      CreateMetadata(/*change_all_fields=*/true);

  DummyExceptionStateForTesting exception_state;
  encoded_frame->setMetadata(new_metadata, exception_state);
  EXPECT_FALSE(exception_state.HadException()) << exception_state.Message();

  EXPECT_EQ(actual_metadata.GetFrameId(), new_metadata->frameId());
  Vector<int64_t> actual_dependencies;
  for (const auto& dependency : actual_metadata.GetFrameDependencies()) {
    actual_dependencies.push_back(dependency);
  }
  EXPECT_EQ(actual_dependencies, new_metadata->dependencies());
  EXPECT_EQ(actual_metadata.GetWidth(), new_metadata->width());
  EXPECT_EQ(actual_metadata.GetHeight(), new_metadata->height());
  EXPECT_EQ(actual_metadata.GetSpatialIndex(), new_metadata->spatialIndex());
  EXPECT_EQ(actual_metadata.GetTemporalIndex(), new_metadata->temporalIndex());
  EXPECT_EQ(actual_metadata.GetSsrc(), new_metadata->synchronizationSource());
  Vector<uint32_t> actual_csrcs;
  for (const auto& dependency : actual_metadata.GetCsrcs()) {
    actual_csrcs.push_back(dependency);
  }
  EXPECT_EQ(actual_csrcs, new_metadata->contributingSources());
}

TEST_F(RTCEncodedVideoFrameTest, SetMetadataOnEmptyFrameFails) {
  V8TestingScope v8_scope;

  std::unique_ptr<MockTransformableVideoFrame> frame =
      std::make_unique<NiceMock<MockTransformableVideoFrame>>();
  MockVP8Metadata(frame.get());

  RTCEncodedVideoFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedVideoFrame>(std::move(frame));
  RTCEncodedVideoFrameMetadata* metadata = encoded_frame->getMetadata();

  // Move the WebRTC frame out, as if the frame had been written into
  // an encoded insertable stream's WritableStream to be sent on.
  encoded_frame->PassWebRtcFrame(v8_scope.GetIsolate(),
                                 /*detach_frame_data=*/false);

  DummyExceptionStateForTesting exception_state;
  encoded_frame->setMetadata(metadata, exception_state);

  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(exception_state.Message(),
            "Cannot setMetadata: underlying webrtc frame is an empty frame.");
}

TEST_F(RTCEncodedVideoFrameTest, SetMetadataRejectsInvalidDependencies) {
  V8TestingScope v8_scope;
  base::test::ScopedFeatureList feature_list_;
  feature_list_.InitWithFeatures(
      /*enabled_features=*/{kAllowRTCEncodedVideoFrameSetMetadataAllFields},
      /*disabled_features=*/{});

  std::unique_ptr<MockTransformableVideoFrame> frame =
      std::make_unique<NiceMock<MockTransformableVideoFrame>>();
  MockVP8Metadata(frame.get());

  EXPECT_CALL(*frame, SetMetadata(_)).Times(0);

  RTCEncodedVideoFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedVideoFrame>(std::move(frame));
  RTCEncodedVideoFrameMetadata* new_metadata = CreateMetadata();
  // Set an invalid dependency - all deps must be less than frame id.
  new_metadata->setDependencies({new_metadata->frameId()});

  DummyExceptionStateForTesting exception_state;
  encoded_frame->setMetadata(new_metadata, exception_state);
  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(exception_state.Message(),
            "Cannot setMetadata: new metadata has invalid frame "
            "dependencies.");
}

TEST_F(RTCEncodedVideoFrameTest, SetMetadataRejectsTooEarlyDependencies) {
  V8TestingScope v8_scope;
  base::test::ScopedFeatureList feature_list_;
  feature_list_.InitWithFeatures(
      /*enabled_features=*/{kAllowRTCEncodedVideoFrameSetMetadataAllFields},
      /*disabled_features=*/{});

  std::unique_ptr<MockTransformableVideoFrame> frame =
      std::make_unique<NiceMock<MockTransformableVideoFrame>>();
  MockVP8Metadata(frame.get());

  EXPECT_CALL(*frame, SetMetadata(_)).Times(0);

  RTCEncodedVideoFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedVideoFrame>(std::move(frame));
  RTCEncodedVideoFrameMetadata* new_metadata = CreateMetadata();
  // Set an invalid dependency - deps must be within 1 << 14 of the frame id.
  new_metadata->setFrameId(1 << 14);
  new_metadata->setDependencies({0});

  DummyExceptionStateForTesting exception_state;
  encoded_frame->setMetadata(new_metadata, exception_state);
  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(exception_state.Message(),
            "Cannot setMetadata: new metadata has invalid frame "
            "dependencies.");
}

TEST_F(RTCEncodedVideoFrameTest, SetMetadataRejectsTooManyDependencies) {
  V8TestingScope v8_scope;
  base::test::ScopedFeatureList feature_list_;
  feature_list_.InitWithFeatures(
      /*enabled_features=*/{kAllowRTCEncodedVideoFrameSetMetadataAllFields},
      /*disabled_features=*/{});

  std::unique_ptr<MockTransformableVideoFrame> frame =
      std::make_unique<NiceMock<MockTransformableVideoFrame>>();
  MockVP8Metadata(frame.get());

  EXPECT_CALL(*frame, SetMetadata(_)).Times(0);

  RTCEncodedVideoFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedVideoFrame>(std::move(frame));
  RTCEncodedVideoFrameMetadata* new_metadata = CreateMetadata();
  // Set too many dependencies.
  new_metadata->setDependencies({1, 2, 3, 4, 5, 6, 7, 8, 9});

  DummyExceptionStateForTesting exception_state;
  encoded_frame->setMetadata(new_metadata, exception_state);
  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(exception_state.Message(),
            "Cannot setMetadata: new metadata has too many dependencies.");
}

TEST_F(RTCEncodedVideoFrameTest, SetMetadataModifiesRtpTimestamp) {
  V8TestingScope v8_scope;

  std::unique_ptr<MockTransformableVideoFrame> frame =
      std::make_unique<NiceMock<MockTransformableVideoFrame>>();
  MockVP8Metadata(frame.get());

  const uint32_t new_timestamp = 7;

  EXPECT_CALL(*frame, GetTimestamp()).WillRepeatedly(Return(1));

  EXPECT_CALL(*frame, SetMetadata(_));
  EXPECT_CALL(*frame, SetRTPTimestamp(new_timestamp));

  RTCEncodedVideoFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedVideoFrame>(std::move(frame));
  RTCEncodedVideoFrameMetadata* metadata = encoded_frame->getMetadata();
  metadata->setRtpTimestamp(new_timestamp);

  DummyExceptionStateForTesting exception_state;

  encoded_frame->setMetadata(metadata, exception_state);
  EXPECT_FALSE(exception_state.HadException()) << exception_state.Message();
}

TEST_F(RTCEncodedVideoFrameTest, ConstructorPreservesVP9CodecSpecifics) {
  V8TestingScope v8_scope;

  std::unique_ptr<MockTransformableVideoFrame> frame =
      std::make_unique<NiceMock<MockTransformableVideoFrame>>();
  webrtc::VideoFrameMetadata webrtc_metadata = MockVP9Metadata(frame.get());

  RTCEncodedVideoFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedVideoFrame>(std::move(frame));
  DummyExceptionStateForTesting exception_state;

  RTCEncodedVideoFrame* new_frame =
      RTCEncodedVideoFrame::Create(encoded_frame, exception_state);
  EXPECT_FALSE(exception_state.HadException()) << exception_state.Message();
  EXPECT_EQ(new_frame->getMetadata()->frameId(), webrtc_metadata.GetFrameId());
  EXPECT_EQ(new_frame->getMetadata()->width(), webrtc_metadata.GetWidth());
  EXPECT_EQ(new_frame->getMetadata()->height(), webrtc_metadata.GetHeight());
  EXPECT_EQ(new_frame->getMetadata()->spatialIndex(),
            webrtc_metadata.GetSpatialIndex());
  EXPECT_EQ(new_frame->getMetadata()->temporalIndex(),
            webrtc_metadata.GetTemporalIndex());
  EXPECT_EQ(new_frame->getMetadata()->synchronizationSource(),
            webrtc_metadata.GetSsrc());
  std::vector<uint32_t> actual_csrcs;
  for (const auto& dependency :
       new_frame->getMetadata()->contributingSources()) {
    actual_csrcs.push_back(dependency);
  }
  EXPECT_EQ(actual_csrcs, webrtc_metadata.GetCsrcs());
}

TEST_F(RTCEncodedVideoFrameTest, ConstructorMissingFieldsFails) {
  V8TestingScope v8_scope;
  base::test::ScopedFeatureList feature_list_;

  std::unique_ptr<MockTransformableVideoFrame> frame =
      std::make_unique<NiceMock<MockTransformableVideoFrame>>();
  MockVP8Metadata(frame.get());
  RTCEncodedVideoFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedVideoFrame>(std::move(frame));
  RTCEncodedVideoFrameOptions* empty_frame_options =
      RTCEncodedVideoFrameOptions::Create();
  empty_frame_options->setMetadata(RTCEncodedVideoFrameMetadata::Create());

  DummyExceptionStateForTesting exception_state;
  RTCEncodedVideoFrame* new_frame = RTCEncodedVideoFrame::Create(
      encoded_frame, empty_frame_options, exception_state);
  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(exception_state.Message(),
            "Cannot create a new VideoFrame: new metadata has member(s) "
            "missing.");
  EXPECT_EQ(new_frame, nullptr);
}

TEST_F(RTCEncodedVideoFrameTest, ConstructorWithoutFeatureFailsModifications) {
  V8TestingScope v8_scope;
  base::test::ScopedFeatureList feature_list_;
  feature_list_.InitWithFeatures(
      /*enabled_features=*/{},
      /*disabled_features=*/{kAllowRTCEncodedVideoFrameSetMetadataAllFields});

  std::unique_ptr<MockTransformableVideoFrame> frame =
      std::make_unique<NiceMock<MockTransformableVideoFrame>>();
  MockVP8Metadata(frame.get());

  webrtc::VideoFrameMetadata actual_metadata;
  EXPECT_CALL(*frame, SetMetadata(_)).Times(0);
  EXPECT_CALL(*frame, GetPayloadType()).WillRepeatedly(Return(1));

  RTCEncodedVideoFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedVideoFrame>(std::move(frame));
  RTCEncodedVideoFrameOptions* frame_options =
      RTCEncodedVideoFrameOptions::Create();
  frame_options->setMetadata(CreateMetadata(/*change_all_fields=*/true));

  DummyExceptionStateForTesting exception_state;
  RTCEncodedVideoFrame* new_frame = RTCEncodedVideoFrame::Create(
      encoded_frame, frame_options, exception_state);
  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(exception_state.Message(),
            "Cannot create a new VideoFrame: invalid modification of "
            "RTCEncodedVideoFrameMetadata.");
  EXPECT_EQ(new_frame, nullptr);
}

TEST_F(RTCEncodedVideoFrameTest, ConstructorWithFeatureAllowsModifications) {
  V8TestingScope v8_scope;
  base::test::ScopedFeatureList feature_list_;
  feature_list_.InitWithFeatures(
      /*enabled_features=*/{kAllowRTCEncodedVideoFrameSetMetadataAllFields},
      /*disabled_features=*/{});

  std::unique_ptr<MockTransformableVideoFrame> frame =
      std::make_unique<NiceMock<MockTransformableVideoFrame>>();
  MockVP8Metadata(frame.get());

  webrtc::VideoFrameMetadata actual_metadata;
  EXPECT_CALL(*frame, SetMetadata(_)).Times(0);
  EXPECT_CALL(*frame, GetPayloadType()).WillRepeatedly(Return(14));

  RTCEncodedVideoFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedVideoFrame>(std::move(frame));

  RTCEncodedVideoFrameMetadata* new_metadata =
      CreateMetadata(/*change_all_fields=*/true);
  RTCEncodedVideoFrameOptions* frame_options =
      RTCEncodedVideoFrameOptions::Create();
  frame_options->setMetadata(new_metadata);

  DummyExceptionStateForTesting exception_state;
  RTCEncodedVideoFrame* new_frame = RTCEncodedVideoFrame::Create(
      encoded_frame, frame_options, exception_state);

  EXPECT_FALSE(exception_state.HadException()) << exception_state.Message();

  EXPECT_EQ(new_frame->getMetadata()->frameId(), new_metadata->frameId());
  Vector<int64_t> actual_dependencies;
  for (const auto& dependency : new_frame->getMetadata()->dependencies()) {
    actual_dependencies.push_back(dependency);
  }
  EXPECT_EQ(actual_dependencies, new_metadata->dependencies());
  EXPECT_EQ(new_frame->getMetadata()->width(), new_metadata->width());
  EXPECT_EQ(new_frame->getMetadata()->height(), new_metadata->height());
  EXPECT_EQ(new_frame->getMetadata()->spatialIndex(),
            new_metadata->spatialIndex());
  EXPECT_EQ(new_frame->getMetadata()->temporalIndex(),
            new_metadata->temporalIndex());
  EXPECT_EQ(new_frame->getMetadata()->synchronizationSource(),
            new_metadata->synchronizationSource());
  Vector<uint32_t> actual_csrcs;
  for (const auto& dependency :
       new_frame->getMetadata()->contributingSources()) {
    actual_csrcs.push_back(dependency);
  }
  EXPECT_EQ(actual_csrcs, new_metadata->contributingSources());
}

TEST_F(RTCEncodedVideoFrameTest, ConstructorFromNull) {
  V8TestingScope v8_scope;
  DummyExceptionStateForTesting exception_state;
  RTCEncodedVideoFrame* new_frame =
      RTCEncodedVideoFrame::Create(nullptr, exception_state);

  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(exception_state.Message(),
            "Cannot create a new VideoFrame from an empty VideoFrame");
  EXPECT_EQ(new_frame, nullptr);
}

TEST_F(RTCEncodedVideoFrameTest, ConstructorOnEmptyFrameWorks) {
  V8TestingScope v8_scope;

  std::unique_ptr<MockTransformableVideoFrame> frame =
      std::make_unique<NiceMock<MockTransformableVideoFrame>>();
  MockVP8Metadata(frame.get());

  RTCEncodedVideoFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedVideoFrame>(std::move(frame));

  // Move the WebRTC frame out, as if the frame had been written into
  // an encoded insertable stream's WritableStream to be sent on.
  encoded_frame->PassWebRtcFrame(v8_scope.GetIsolate(),
                                 /*detach_frame_data=*/false);

  DummyExceptionStateForTesting exception_state;
  RTCEncodedVideoFrame* new_frame =
      RTCEncodedVideoFrame::Create(encoded_frame, exception_state);

  EXPECT_FALSE(exception_state.HadException());
  EXPECT_NE(new_frame, nullptr);
  EXPECT_EQ(new_frame->type(), "empty");
}

TEST_F(RTCEncodedVideoFrameTest, ConstructorWithMetadataOnEmptyFrameFails) {
  V8TestingScope v8_scope;

  std::unique_ptr<MockTransformableVideoFrame> frame =
      std::make_unique<NiceMock<MockTransformableVideoFrame>>();
  MockVP8Metadata(frame.get());

  RTCEncodedVideoFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedVideoFrame>(std::move(frame));
  RTCEncodedVideoFrameOptions* frame_options =
      RTCEncodedVideoFrameOptions::Create();
  frame_options->setMetadata(encoded_frame->getMetadata());
  // Move the WebRTC frame out, as if the frame had been written into
  // an encoded insertable stream's WritableStream to be sent on.
  encoded_frame->PassWebRtcFrame(v8_scope.GetIsolate(),
                                 /*detach_frame_data=*/false);

  DummyExceptionStateForTesting exception_state;
  RTCEncodedVideoFrame* new_frame = RTCEncodedVideoFrame::Create(
      encoded_frame, frame_options, exception_state);

  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(exception_state.Message(),
            "Cannot create a new VideoFrame: underlying webrtc frame is "
            "an empty frame.");
  EXPECT_EQ(new_frame, nullptr);
}

TEST_F(RTCEncodedVideoFrameTest, ConstructorRejectsInvalidDependencies) {
  V8TestingScope v8_scope;
  base::test::ScopedFeatureList feature_list_;
  feature_list_.InitWithFeatures(
      /*enabled_features=*/{kAllowRTCEncodedVideoFrameSetMetadataAllFields},
      /*disabled_features=*/{});

  std::unique_ptr<MockTransformableVideoFrame> frame =
      std::make_unique<NiceMock<MockTransformableVideoFrame>>();
  MockVP8Metadata(frame.get());

  EXPECT_CALL(*frame, SetMetadata(_)).Times(0);

  RTCEncodedVideoFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedVideoFrame>(std::move(frame));
  RTCEncodedVideoFrameMetadata* new_metadata = CreateMetadata();
  // Set an invalid dependency - all deps must be less than frame id.
  new_metadata->setDependencies({new_metadata->frameId()});

  RTCEncodedVideoFrameOptions* frame_options =
      RTCEncodedVideoFrameOptions::Create();
  frame_options->setMetadata(new_metadata);

  DummyExceptionStateForTesting exception_state;
  RTCEncodedVideoFrame* new_frame = RTCEncodedVideoFrame::Create(
      encoded_frame, frame_options, exception_state);
  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(exception_state.Message(),
            "Cannot create a new VideoFrame: new metadata has invalid "
            "frame dependencies.");
  EXPECT_EQ(new_frame, nullptr);
}

TEST_F(RTCEncodedVideoFrameTest, ConstructorCopiesMetadata) {
  V8TestingScope v8_scope;

  std::unique_ptr<MockTransformableVideoFrame> frame =
      std::make_unique<NiceMock<MockTransformableVideoFrame>>();
  MockVP8Metadata(frame.get());
  EXPECT_CALL(*frame, GetTimestamp()).WillRepeatedly(Return(1));

  RTCEncodedVideoFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedVideoFrame>(std::move(frame));
  DummyExceptionStateForTesting exception_state;
  RTCEncodedVideoFrame* new_frame =
      RTCEncodedVideoFrame::Create(encoded_frame, exception_state);

  EXPECT_FALSE(exception_state.HadException()) << exception_state.Message();

  EXPECT_EQ(new_frame->getMetadata()->frameId(),
            encoded_frame->getMetadata()->frameId());
  EXPECT_EQ(new_frame->getMetadata()->dependencies(),
            encoded_frame->getMetadata()->dependencies());
  EXPECT_EQ(new_frame->getMetadata()->width(),
            encoded_frame->getMetadata()->width());
  EXPECT_EQ(new_frame->getMetadata()->height(),
            encoded_frame->getMetadata()->height());
  EXPECT_EQ(new_frame->getMetadata()->spatialIndex(),
            encoded_frame->getMetadata()->spatialIndex());
  EXPECT_EQ(new_frame->getMetadata()->temporalIndex(),
            encoded_frame->getMetadata()->temporalIndex());
  EXPECT_EQ(new_frame->getMetadata()->synchronizationSource(),
            encoded_frame->getMetadata()->synchronizationSource());
  EXPECT_EQ(new_frame->getMetadata()->contributingSources(),
            encoded_frame->getMetadata()->contributingSources());
  EXPECT_EQ(new_frame->getMetadata()->rtpTimestamp(),
            encoded_frame->getMetadata()->rtpTimestamp());
}

TEST_F(RTCEncodedVideoFrameTest, ConstructorWithMetadataGetsNewMetadata) {
  V8TestingScope v8_scope;

  std::unique_ptr<MockTransformableVideoFrame> frame =
      std::make_unique<NiceMock<MockTransformableVideoFrame>>();
  MockVP8Metadata(frame.get());
  EXPECT_CALL(*frame, GetPayloadType()).WillRepeatedly(Return(1));

  RTCEncodedVideoFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedVideoFrame>(std::move(frame));
  RTCEncodedVideoFrameMetadata* new_metadata = CreateMetadata();
  RTCEncodedVideoFrameOptions* frame_options =
      RTCEncodedVideoFrameOptions::Create();
  frame_options->setMetadata(new_metadata);

  DummyExceptionStateForTesting exception_state;
  RTCEncodedVideoFrame* new_frame = RTCEncodedVideoFrame::Create(
      encoded_frame, frame_options, exception_state);

  EXPECT_FALSE(exception_state.HadException()) << exception_state.Message();

  // |new_frame|'s metadata is same as |new_metadata|.
  EXPECT_EQ(new_frame->getMetadata()->frameId(), new_metadata->frameId());
  Vector<int64_t> actual_dependencies;
  for (const auto& dependency : new_frame->getMetadata()->dependencies()) {
    actual_dependencies.push_back(dependency);
  }
  EXPECT_EQ(actual_dependencies, new_metadata->dependencies());
  EXPECT_EQ(new_frame->getMetadata()->width(), new_metadata->width());
  EXPECT_EQ(new_frame->getMetadata()->height(), new_metadata->height());
  EXPECT_EQ(new_frame->getMetadata()->spatialIndex(),
            new_metadata->spatialIndex());
  EXPECT_EQ(new_frame->getMetadata()->temporalIndex(),
            new_metadata->temporalIndex());
  EXPECT_EQ(new_frame->getMetadata()->synchronizationSource(),
            new_metadata->synchronizationSource());
  Vector<uint32_t> actual_csrcs;
  for (const auto& dependency :
       new_frame->getMetadata()->contributingSources()) {
    actual_csrcs.push_back(dependency);
  }
  EXPECT_EQ(actual_csrcs, new_metadata->contributingSources());

  // |new_frame|'s metadata is different from original |encoded_frame|'s
  // metadata.
  EXPECT_NE(new_frame->getMetadata()->frameId(),
            encoded_frame->getMetadata()->frameId());
  EXPECT_NE(new_frame->getMetadata()->dependencies(),
            encoded_frame->getMetadata()->dependencies());
  EXPECT_NE(new_frame->getMetadata()->rtpTimestamp(),
            encoded_frame->getMetadata()->rtpTimestamp());
}

TEST_F(RTCEncodedVideoFrameTest,
       ConstructorWithMetadataDoesNotAllowChangingPayloadType) {
  V8TestingScope v8_scope;

  std::unique_ptr<MockTransformableVideoFrame> frame =
      std::make_unique<NiceMock<MockTransformableVideoFrame>>();
  MockVP8Metadata(frame.get());

  webrtc::VideoFrameMetadata actual_metadata;
  EXPECT_CALL(*frame, SetMetadata(_)).Times(0);
  EXPECT_CALL(*frame, GetPayloadType()).WillRepeatedly(Return(14));

  RTCEncodedVideoFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedVideoFrame>(std::move(frame));
  RTCEncodedVideoFrameOptions* frame_options =
      RTCEncodedVideoFrameOptions::Create();
  frame_options->setMetadata(CreateMetadata());

  DummyExceptionStateForTesting exception_state;
  RTCEncodedVideoFrame* new_frame = RTCEncodedVideoFrame::Create(
      encoded_frame, frame_options, exception_state);
  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(exception_state.Message(),
            "Cannot create a new VideoFrame: invalid modification of "
            "payloadType in RTCEncodedVideoFrameMetadata.");
  EXPECT_EQ(new_frame, nullptr);
}

TEST_F(RTCEncodedVideoFrameTest, ReadingDataOnEmptyFrameGivesDetachedFrame) {
  V8TestingScope v8_scope;

  std::unique_ptr<MockTransformableVideoFrame> frame =
      std::make_unique<NiceMock<MockTransformableVideoFrame>>();

  RTCEncodedVideoFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedVideoFrame>(std::move(frame));
  encoded_frame->PassWebRtcFrame(v8_scope.GetIsolate(),
                                 /*detach_frame_data=*/false);

  DOMArrayBuffer* data = encoded_frame->data(v8_scope.GetExecutionContext());
  EXPECT_NE(data, nullptr);
  EXPECT_TRUE(data->IsDetached());
}

TEST_F(RTCEncodedVideoFrameTest, PassWebRTCDetachesFrameData) {
  V8TestingScope v8_scope;

  std::unique_ptr<MockTransformableVideoFrame> frame =
      std::make_unique<NiceMock<MockTransformableVideoFrame>>();

  RTCEncodedVideoFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedVideoFrame>(std::move(frame));

  DOMArrayBuffer* data = encoded_frame->data(v8_scope.GetExecutionContext());
  encoded_frame->PassWebRtcFrame(v8_scope.GetIsolate(),
                                 /*detach_frame_data=*/true);
  EXPECT_NE(data, nullptr);
  EXPECT_TRUE(data->IsDetached());
}

}  // namespace blink
```