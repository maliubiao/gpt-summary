Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Subject:** The filename `rtc_encoded_audio_frame_test.cc` and the namespace `blink` and the path `blink/renderer/modules/peerconnection` immediately tell us this file tests the `RTCEncodedAudioFrame` class, likely within the WebRTC implementation of the Blink rendering engine.

2. **Understand the Purpose of a Test File:**  A test file's primary function is to verify the functionality of a specific class or component. It does this by creating instances of the class, calling its methods, and asserting that the results are as expected. This involves setting up controlled scenarios and checking for correct behavior under various conditions.

3. **Examine the Includes:** The `#include` statements provide valuable context:
    * `rtc_encoded_audio_frame.h`:  This confirms the target of the tests.
    * `base/test/scoped_feature_list.h`: Suggests feature flag testing might be present (though not explicitly used in this snippet).
    * `testing/gmock/include/gmock/gmock.h` and `testing/gtest/include/gtest/gtest.h`: Indicate the use of Google Mock and Google Test frameworks for creating and running tests. This tells us the testing style.
    * `renderer/bindings/core/v8/v8_binding_for_testing.h` and the other `v8_rtc_*` headers: These point to the interaction of `RTCEncodedAudioFrame` with the V8 JavaScript engine. Specifically, it handles the binding between the C++ implementation and the JavaScript API.
    * `core/typed_arrays/dom_array_buffer.h`: Indicates that the `RTCEncodedAudioFrame` likely deals with raw data buffers.
    * `rtc_encoded_audio_frame_delegate.h`: Suggests a delegate pattern might be used for some operations (though not directly tested in this snippet).
    * `platform/testing/task_environment.h`:  Implies that the tests might involve asynchronous operations or a controlled environment for task execution.
    * `third_party/webrtc/api/test/mock_transformable_audio_frame.h`: This is crucial. It reveals that the tests use a *mock* object (`MockTransformableAudioFrame`) instead of a real WebRTC audio frame. This is common in unit testing to isolate the component under test and avoid dependencies on external systems.

4. **Analyze the Test Fixture:** The `RTCEncodedAudioFrameTest` class inherits from `testing::Test`. This sets up the basic structure for a group of related tests. The `test::TaskEnvironment task_environment_;` member likely sets up a controlled environment for asynchronous operations within the tests.

5. **Deconstruct Individual Tests:** Go through each `TEST_F` function:
    * **`GetMetadataReturnsCorrectMetadata`:**  Checks if retrieving the metadata of an `RTCEncodedAudioFrame` returns the expected values based on the underlying mocked WebRTC frame. *Key observation: It uses `ON_CALL` and `WillByDefault` to set up the mock's behavior.*
    * **`SetMetadataOnEmptyFrameFails`:** Tests the scenario where `setMetadata` is called on an `RTCEncodedAudioFrame` that has been "emptied" using `PassWebRtcFrame`. It verifies that this operation fails with a specific error message. *Key observation: It uses `EXPECT_CALL` and `Times(0)` to assert that `SetRTPTimestamp` on the mock is *not* called.*
    * **`SetMetadataModifiesRtpTimestamp`:** Verifies that setting metadata through `setMetadata` correctly updates the RTP timestamp in the underlying WebRTC frame. *Key observation: `EXPECT_CALL(*frame, SetRTPTimestamp(110)).Times(1);` confirms the mock method is called.*
    * **`ConstructorFromNull`:** Checks that attempting to create an `RTCEncodedAudioFrame` from a null WebRTC frame results in an error.
    * **`ConstructorOnEmptyFrameHasEmptyMetadata`:** Tests the metadata of an `RTCEncodedAudioFrame` created from an "emptied" frame.
    * **`ConstructorWithMetadataOnEmptyFrameFails`:**  Similar to `SetMetadataOnEmptyFrameFails`, but checks the constructor.
    * **`ConstructorWithRTPTimestampMetadataOnEmptyFrameFails`:** Another constructor test focusing on setting RTP timestamp on an empty frame.
    * **`ConstructorWithMetadataModifiesRtpTimestamp`:**  Checks that the constructor, when provided with metadata, updates the RTP timestamp correctly.
    * **`ConstructorCopiesMetadata` and `ConstructorWithMetadataCopiesMetadata`:** Verify that the constructor creates a *copy* of the metadata, so modifications to the new frame's metadata don't affect the original.
    * **`ReadingDataOnEmptyFrameGivesDetachedFrame`:** Checks that accessing the data of an "emptied" frame results in a detached `DOMArrayBuffer`.
    * **`PassWebRTCDetachesFrameData`:** Verifies that calling `PassWebRtcFrame` with `detach_frame_data=true` detaches the underlying data buffer.

6. **Identify Relationships with Web Technologies:**
    * **JavaScript:** The presence of `v8_rtc_*` headers strongly indicates interaction with JavaScript. The `RTCEncodedAudioFrame` likely corresponds to a JavaScript object accessible through the WebRTC API. The tests using `V8TestingScope` confirm this interaction by providing a controlled V8 environment.
    * **HTML/CSS:** While not directly involved in *this specific test file*, the larger context of WebRTC implies that the `RTCEncodedAudioFrame` is used in conjunction with JavaScript APIs called from HTML pages, potentially styled with CSS (though the core data handling is independent of CSS).

7. **Infer Potential User Errors and Debugging:** Based on the test cases, we can deduce potential user errors, such as trying to modify metadata after the underlying frame has been "passed" or trying to create a frame from a null source. The test file itself serves as a debugging tool – if a bug is found, a new test case can be written to reproduce it. The steps to reach this code involve using the WebRTC API in JavaScript to send or receive encoded audio.

8. **Structure the Answer:** Organize the findings into logical sections as requested by the prompt: functionality, relationship to web technologies, logical reasoning, user errors, and debugging context. Use the specific examples from the test cases to illustrate each point.

9. **Refine and Review:**  Read through the answer to ensure clarity, accuracy, and completeness. Double-check the assumptions and inferences made. For example, initially, I might have just said "deals with audio data," but looking closer at `MockTransformableAudioFrame` clarifies that it's about *transformable* audio frames, which is a specific concept within WebRTC.
这个文件 `rtc_encoded_audio_frame_test.cc` 是 Chromium Blink 引擎中用于测试 `RTCEncodedAudioFrame` 类的单元测试文件。`RTCEncodedAudioFrame` 类在 WebRTC (Web Real-Time Communication) 模块中，用于表示编码后的音频帧。

以下是该文件的功能分解：

**1. 功能概述:**

* **测试 `RTCEncodedAudioFrame` 类的功能:**  该文件包含了多个独立的测试用例 (使用 Google Test 框架的 `TEST_F`)，用于验证 `RTCEncodedAudioFrame` 类的各种方法和行为是否符合预期。
* **测试元数据 (Metadata) 的处理:**  重点测试了如何获取、设置和复制编码音频帧的元数据，包括同步源 (SSRC)、贡献源 (CSRC)、负载类型 (Payload Type)、MIME 类型、序列号、绝对捕获时间戳 (Absolute Capture Timestamp) 和 RTP 时间戳 (RTP Timestamp)。
* **测试生命周期管理:**  测试了创建、销毁和传递底层的 WebRTC 音频帧 (使用 `MockTransformableAudioFrame` 模拟) 的场景。
* **测试异常处理:**  测试了在非法操作下是否会抛出预期的异常，例如尝试在空帧上设置元数据或从空指针创建帧。
* **使用 Mock 对象进行隔离测试:**  使用了 `MockTransformableAudioFrame` 来模拟底层的 WebRTC 音频帧，使得测试可以独立进行，而不需要依赖真实的 WebRTC 实现。

**2. 与 JavaScript, HTML, CSS 的关系举例:**

`RTCEncodedAudioFrame` 类本身是在 C++ 层实现的，但它直接与 WebRTC 的 JavaScript API 相关联。

* **JavaScript:**
    * **获取编码后的音频帧:**  在 WebRTC 的 `RTCPeerConnection` API 中，当使用编码转换 (Encoded Transform) 或可插入媒体流 (Insertable Streams) 功能时，JavaScript 可以接收到 `RTCRtpReceiver` 发送过来的 `RTCRtpScriptTransform` 中转换后的 `RTCEncodedAudioFrame` 对象。
    * **操作元数据:** JavaScript 可以通过 `RTCEncodedAudioFrame` 对象的属性（如 `synchronizationSource`、`contributingSources`、`rtpTimestamp` 等，尽管这些属性可能在 JavaScript 中以不同的方式暴露）来访问和修改音频帧的元数据。例如，用户可能想要修改 RTP 时间戳以进行同步或其他处理。
    * **访问音频数据:**  JavaScript 可以通过 `RTCEncodedAudioFrame.data` 属性获取编码后的音频数据，这是一个 `ArrayBuffer` 对象。
    * **创建新的编码音频帧:**  JavaScript 可能需要基于现有的帧创建新的编码音频帧，并可以设置新的元数据。

    **举例说明:**

    ```javascript
    // 假设 encodedAudioFrame 是一个从 RTCRtpReceiver 获取的 RTCEncodedAudioFrame 对象
    console.log("同步源:", encodedAudioFrame.synchronizationSource); // 获取同步源 (如果暴露)
    console.log("RTP 时间戳:", encodedAudioFrame.rtpTimestamp);     // 获取 RTP 时间戳 (如果暴露)

    const newData = new ArrayBuffer(1024); // 一些新的音频数据
    const newMetadata = { rtpTimestamp: encodedAudioFrame.rtpTimestamp + 100 };
    const newEncodedAudioFrame = new RTCEncodedAudioFrame(newData, newMetadata);
    ```

* **HTML:**  HTML 定义了网页的结构，其中可能包含使用 WebRTC 功能的 JavaScript 代码。例如，一个网页可能包含用于发起和管理 WebRTC 连接的按钮和脚本。
* **CSS:** CSS 用于网页的样式，与 `RTCEncodedAudioFrame` 的功能没有直接关系。CSS 可能会影响包含 WebRTC 功能的网页的布局和外观，但不会影响音频帧的处理逻辑。

**3. 逻辑推理 (假设输入与输出):**

以下是一些基于测试用例的逻辑推理：

* **假设输入:**  一个已经创建并填充了元数据的 `MockTransformableAudioFrame` 对象。
* **输出:** `RTCEncodedAudioFrame::getMetadata()` 方法应该返回一个 `RTCEncodedAudioFrameMetadata` 对象，其属性值与 `MockTransformableAudioFrame` 中设置的值一致。

* **假设输入:**  一个已经通过 `PassWebRtcFrame` 方法传递了底层 WebRTC 帧的 `RTCEncodedAudioFrame` 对象 (此时底层帧被认为是 "空的")，并且尝试调用 `setMetadata` 方法设置新的元数据。
* **输出:**  `setMetadata` 方法应该抛出一个异常，指示无法修改元数据，并且异常消息应该包含 "Invalid modification of RTCEncodedAudioFrameMetadata"。

* **假设输入:**  一个已经创建的 `RTCEncodedAudioFrame` 对象，并且调用其构造函数创建一个新的 `RTCEncodedAudioFrame` 对象。
* **输出:** 新创建的 `RTCEncodedAudioFrame` 对象的元数据应该是原始帧元数据的副本。

**4. 用户或编程常见的使用错误举例:**

* **尝试在底层 WebRTC 帧已经被传递后修改元数据:**  一旦 `RTCEncodedAudioFrame` 对象通过 `PassWebRtcFrame` 将其底层的 WebRTC 帧交出，就不能再修改其元数据。这是一个常见的错误，因为用户可能没有意识到帧的生命周期管理。测试用例 `SetMetadataOnEmptyFrameFails` 就覆盖了这种情况。
* **从空指针创建 `RTCEncodedAudioFrame`:**  尝试使用 `RTCEncodedAudioFrame::Create(nullptr, ...)` 创建对象会导致异常。这表明 API 设计上不允许使用空指针作为输入。测试用例 `ConstructorFromNull` 验证了这一点。
* **假设 `RTCEncodedAudioFrame` 的元数据可以随意修改:**  `RTCEncodedAudioFrame` 的某些行为（如 `PassWebRtcFrame`）可能会冻结其状态，之后尝试修改元数据会导致错误。用户需要理解这些状态转换。
* **在 JavaScript 中不正确地操作元数据对象:**  如果 JavaScript 试图修改的元数据属性与 C++ 层的约束不符，或者尝试设置无效的值，可能会导致错误或未定义的行为。

**5. 用户操作如何一步步到达这里 (调试线索):**

假设开发者正在调试一个 WebRTC 应用中关于音频帧处理的问题：

1. **用户发起或接收音频流:**  用户在浏览器中打开一个使用 WebRTC 的网页，并成功建立了一个音视频通话连接。
2. **编码后的音频帧到达:**  当远端发送音频时，浏览器接收到编码后的音频数据。
3. **使用 Encoded Transform 或 Insertable Streams:**  如果 JavaScript 代码使用了 `RTCRtpReceiver.transform` (Encoded Transform) 或直接访问了 `RTCRtpReceiver` 的可读流 (Insertable Streams)，那么 JavaScript 代码会接收到 `RTCEncodedAudioFrame` 对象。
4. **尝试访问或修改音频帧的元数据:**  JavaScript 代码可能会尝试读取 `RTCEncodedAudioFrame` 对象的属性，例如 `synchronizationSource` 或 `rtpTimestamp`，以进行某些自定义处理或分析。
5. **遇到问题或错误:**  如果在 JavaScript 中访问或操作 `RTCEncodedAudioFrame` 对象时出现意外行为（例如，获取的元数据不正确，或者尝试修改元数据导致错误），开发者可能会怀疑 C++ 层的 `RTCEncodedAudioFrame` 实现有问题。
6. **查看 C++ 代码和测试:**  开发者可能会查看 `blink/renderer/modules/peerconnection/rtc_encoded_audio_frame.cc` 的实现代码，并查看 `rtc_encoded_audio_frame_test.cc` 中的测试用例，以了解 `RTCEncodedAudioFrame` 的预期行为和如何正确使用它。
7. **运行测试:**  开发者可能会本地编译 Chromium 并运行 `rtc_encoded_audio_frame_test`，以验证 `RTCEncodedAudioFrame` 的基本功能是否正常。如果测试失败，则表明 C++ 实现存在 bug。
8. **调试 C++ 代码:**  如果测试失败或在实际应用中遇到问题，开发者可能需要使用 C++ 调试器来跟踪 `RTCEncodedAudioFrame` 对象的生命周期和元数据的变化，以找出问题的根源。测试用例中的 `MockTransformableAudioFrame` 可以帮助在隔离的环境中重现问题。

总而言之，`rtc_encoded_audio_frame_test.cc` 是确保 `RTCEncodedAudioFrame` 类在各种场景下都能正确工作的关键组成部分，它帮助开发者理解和调试与 WebRTC 编码音频帧处理相关的潜在问题。

Prompt: 
```
这是目录为blink/renderer/modules/peerconnection/rtc_encoded_audio_frame_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_audio_frame.h"

#include "base/test/scoped_feature_list.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_codec_specifics_vp_8.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_encoded_audio_frame_metadata.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_encoded_audio_frame_options.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_audio_frame_delegate.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/webrtc/api/test/mock_transformable_audio_frame.h"

using testing::_;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;
using testing::SaveArg;

using webrtc::MockTransformableAudioFrame;

namespace blink {

class RTCEncodedAudioFrameTest : public testing::Test {
  test::TaskEnvironment task_environment_;
};

void MockMetadata(MockTransformableAudioFrame* frame) {
  ON_CALL(*frame, GetSsrc()).WillByDefault(Return(7));
  std::array<uint32_t, 2> csrcs{6, 4};
  ON_CALL(*frame, GetContributingSources()).WillByDefault(Return(csrcs));
  ON_CALL(*frame, GetPayloadType()).WillByDefault(Return(13));
  ON_CALL(*frame, SequenceNumber()).WillByDefault(Return(20));
  ON_CALL(*frame, AbsoluteCaptureTimestamp()).WillByDefault(Return(70050));
  ON_CALL(*frame, GetTimestamp()).WillByDefault(Return(17));
  ON_CALL(*frame, GetMimeType()).WillByDefault(Return("image"));
}

RTCEncodedAudioFrameMetadata* CreateAudioMetadata() {
  RTCEncodedAudioFrameMetadata* new_metadata =
      RTCEncodedAudioFrameMetadata::Create();
  new_metadata->setSynchronizationSource(7);
  new_metadata->setContributingSources({6, 4});
  new_metadata->setPayloadType(13);
  new_metadata->setMimeType("image");
  new_metadata->setSequenceNumber(20);
  new_metadata->setAbsCaptureTime(70050);
  new_metadata->setRtpTimestamp(110);
  return new_metadata;
}

TEST_F(RTCEncodedAudioFrameTest, GetMetadataReturnsCorrectMetadata) {
  V8TestingScope v8_scope;

  std::unique_ptr<MockTransformableAudioFrame> frame =
      std::make_unique<MockTransformableAudioFrame>();
  MockMetadata(frame.get());

  RTCEncodedAudioFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedAudioFrame>(std::move(frame));

  RTCEncodedAudioFrameMetadata* retrieved_metadata =
      encoded_frame->getMetadata();
  EXPECT_EQ(7u, retrieved_metadata->synchronizationSource());
  ASSERT_EQ(2u, retrieved_metadata->contributingSources().size());
  EXPECT_EQ(6u, retrieved_metadata->contributingSources()[0]);
  EXPECT_EQ(4u, retrieved_metadata->contributingSources()[1]);
  EXPECT_EQ(13, retrieved_metadata->payloadType());
  EXPECT_EQ("image", retrieved_metadata->mimeType());
  EXPECT_EQ(20u, retrieved_metadata->sequenceNumber());
  EXPECT_EQ(70050u, retrieved_metadata->absCaptureTime());
  EXPECT_EQ(17u, retrieved_metadata->rtpTimestamp());
}

TEST_F(RTCEncodedAudioFrameTest, SetMetadataOnEmptyFrameFails) {
  V8TestingScope v8_scope;

  std::unique_ptr<MockTransformableAudioFrame> frame =
      std::make_unique<NiceMock<MockTransformableAudioFrame>>();
  MockMetadata(frame.get());

  EXPECT_CALL(*frame, SetRTPTimestamp(_)).Times(0);

  RTCEncodedAudioFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedAudioFrame>(std::move(frame));
  encoded_frame->PassWebRtcFrame(v8_scope.GetIsolate(),
                                 /*detach_frame_data=*/false);

  RTCEncodedAudioFrameMetadata* new_metadata = CreateAudioMetadata();

  DummyExceptionStateForTesting exception_state;
  encoded_frame->setMetadata(new_metadata, exception_state);
  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(exception_state.Message(),
            "Cannot setMetadata: Invalid modification of "
            "RTCEncodedAudioFrameMetadata. Bad "
            "synchronizationSource");
}

TEST_F(RTCEncodedAudioFrameTest, SetMetadataModifiesRtpTimestamp) {
  V8TestingScope v8_scope;

  std::unique_ptr<MockTransformableAudioFrame> frame =
      std::make_unique<NiceMock<MockTransformableAudioFrame>>();
  MockMetadata(frame.get());
  EXPECT_CALL(*frame, SetRTPTimestamp(110)).Times(1);

  RTCEncodedAudioFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedAudioFrame>(std::move(frame));

  EXPECT_EQ(encoded_frame->getMetadata()->rtpTimestamp(), 17u);
  RTCEncodedAudioFrameMetadata* new_metadata = CreateAudioMetadata();

  DummyExceptionStateForTesting exception_state;
  encoded_frame->setMetadata(new_metadata, exception_state);
  EXPECT_FALSE(exception_state.HadException()) << exception_state.Message();
}

TEST_F(RTCEncodedAudioFrameTest, ConstructorFromNull) {
  V8TestingScope v8_scope;
  DummyExceptionStateForTesting exception_state;
  RTCEncodedAudioFrame* new_frame =
      RTCEncodedAudioFrame::Create(nullptr, exception_state);

  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(exception_state.Message(),
            "Cannot create a new AudioFrame: input Audioframe is empty.");
  EXPECT_EQ(new_frame, nullptr);
}

TEST_F(RTCEncodedAudioFrameTest, ConstructorOnEmptyFrameHasEmptyMetadata) {
  V8TestingScope v8_scope;

  std::unique_ptr<MockTransformableAudioFrame> frame =
      std::make_unique<NiceMock<MockTransformableAudioFrame>>();
  MockMetadata(frame.get());

  EXPECT_CALL(*frame, SetRTPTimestamp(_)).Times(0);

  RTCEncodedAudioFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedAudioFrame>(std::move(frame));
  encoded_frame->PassWebRtcFrame(v8_scope.GetIsolate(),
                                 /*detach_frame_data=*/false);

  DummyExceptionStateForTesting exception_state;
  RTCEncodedAudioFrame* new_frame =
      RTCEncodedAudioFrame::Create(encoded_frame, exception_state);

  EXPECT_FALSE(exception_state.HadException());
  EXPECT_FALSE(new_frame->getMetadata()->hasSynchronizationSource());
  EXPECT_EQ(new_frame->getMetadata()->contributingSources().size(), 0u);
  EXPECT_FALSE(new_frame->getMetadata()->hasPayloadType());
  EXPECT_FALSE(new_frame->getMetadata()->hasMimeType());
  EXPECT_FALSE(new_frame->getMetadata()->hasSequenceNumber());
  EXPECT_FALSE(new_frame->getMetadata()->hasAbsCaptureTime());
  EXPECT_EQ(new_frame->getMetadata()->rtpTimestamp(), 0u);
}

TEST_F(RTCEncodedAudioFrameTest, ConstructorWithMetadataOnEmptyFrameFails) {
  V8TestingScope v8_scope;

  std::unique_ptr<MockTransformableAudioFrame> frame =
      std::make_unique<NiceMock<MockTransformableAudioFrame>>();
  MockMetadata(frame.get());

  EXPECT_CALL(*frame, SetRTPTimestamp(_)).Times(0);

  RTCEncodedAudioFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedAudioFrame>(std::move(frame));
  encoded_frame->PassWebRtcFrame(v8_scope.GetIsolate(),
                                 /*detach_frame_data=*/false);

  RTCEncodedAudioFrameOptions* frame_options =
      RTCEncodedAudioFrameOptions::Create();
  frame_options->setMetadata(CreateAudioMetadata());

  DummyExceptionStateForTesting exception_state;
  RTCEncodedAudioFrame* new_frame = RTCEncodedAudioFrame::Create(
      encoded_frame, frame_options, exception_state);

  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(exception_state.Message(),
            "Cannot create a new AudioFrame: Invalid modification of "
            "RTCEncodedAudioFrameMetadata. Bad "
            "synchronizationSource");
  EXPECT_EQ(new_frame, nullptr);
}

TEST_F(RTCEncodedAudioFrameTest,
       ConstructorWithRTPTimestampMetadataOnEmptyFrameFails) {
  V8TestingScope v8_scope;

  std::unique_ptr<MockTransformableAudioFrame> frame =
      std::make_unique<NiceMock<MockTransformableAudioFrame>>();
  MockMetadata(frame.get());

  EXPECT_CALL(*frame, SetRTPTimestamp(_)).Times(0);

  RTCEncodedAudioFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedAudioFrame>(std::move(frame));
  encoded_frame->PassWebRtcFrame(v8_scope.GetIsolate(),
                                 /*detach_frame_data=*/false);

  RTCEncodedAudioFrameMetadata* new_metadata =
      RTCEncodedAudioFrameMetadata::Create();
  new_metadata->setContributingSources({});
  new_metadata->setRtpTimestamp(110);
  RTCEncodedAudioFrameOptions* frame_options =
      RTCEncodedAudioFrameOptions::Create();
  frame_options->setMetadata(new_metadata);

  DummyExceptionStateForTesting exception_state;
  RTCEncodedAudioFrame* new_frame = RTCEncodedAudioFrame::Create(
      encoded_frame, frame_options, exception_state);

  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(
      exception_state.Message(),
      "Cannot create a new AudioFrame: Underlying webrtc frame doesn't exist.");
  EXPECT_EQ(new_frame, nullptr);
}

TEST_F(RTCEncodedAudioFrameTest, ConstructorWithMetadataModifiesRtpTimestamp) {
  V8TestingScope v8_scope;
  const uint32_t new_timestamp = 110;
  std::unique_ptr<MockTransformableAudioFrame> frame =
      std::make_unique<NiceMock<MockTransformableAudioFrame>>();
  MockMetadata(frame.get());

  RTCEncodedAudioFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedAudioFrame>(std::move(frame));

  EXPECT_EQ(encoded_frame->getMetadata()->rtpTimestamp(), 17u);
  RTCEncodedAudioFrameMetadata* new_metadata = encoded_frame->getMetadata();
  new_metadata->setRtpTimestamp(new_timestamp);
  RTCEncodedAudioFrameOptions* frame_options =
      RTCEncodedAudioFrameOptions::Create();
  frame_options->setMetadata(new_metadata);

  DummyExceptionStateForTesting exception_state;
  RTCEncodedAudioFrame* new_frame = RTCEncodedAudioFrame::Create(
      encoded_frame, frame_options, exception_state);
  EXPECT_FALSE(exception_state.HadException()) << exception_state.Message();
  EXPECT_EQ(new_frame->getMetadata()->rtpTimestamp(), new_timestamp);
  EXPECT_NE(encoded_frame->getMetadata()->rtpTimestamp(), new_timestamp);
}

TEST_F(RTCEncodedAudioFrameTest, ConstructorCopiesMetadata) {
  V8TestingScope v8_scope;

  std::unique_ptr<MockTransformableAudioFrame> frame =
      std::make_unique<NiceMock<MockTransformableAudioFrame>>();
  MockMetadata(frame.get());

  RTCEncodedAudioFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedAudioFrame>(std::move(frame));
  DummyExceptionStateForTesting exception_state;
  RTCEncodedAudioFrame* new_frame =
      RTCEncodedAudioFrame::Create(encoded_frame, exception_state);

  EXPECT_FALSE(exception_state.HadException()) << exception_state.Message();
  RTCEncodedAudioFrameMetadata* new_frame_metadata = new_frame->getMetadata();

  EXPECT_EQ(7u, new_frame_metadata->synchronizationSource());
  ASSERT_EQ(2u, new_frame_metadata->contributingSources().size());
  EXPECT_EQ(6u, new_frame_metadata->contributingSources()[0]);
  EXPECT_EQ(4u, new_frame_metadata->contributingSources()[1]);
  EXPECT_EQ(13, new_frame_metadata->payloadType());
  EXPECT_EQ("image", new_frame_metadata->mimeType());
  EXPECT_EQ(20u, new_frame_metadata->sequenceNumber());
  EXPECT_EQ(70050u, new_frame_metadata->absCaptureTime());
  EXPECT_EQ(17u, new_frame_metadata->rtpTimestamp());
}

TEST_F(RTCEncodedAudioFrameTest, ConstructorWithMetadataCopiesMetadata) {
  V8TestingScope v8_scope;

  std::unique_ptr<MockTransformableAudioFrame> frame =
      std::make_unique<NiceMock<MockTransformableAudioFrame>>();
  MockMetadata(frame.get());

  RTCEncodedAudioFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedAudioFrame>(std::move(frame));
  DummyExceptionStateForTesting exception_state;
  RTCEncodedAudioFrameMetadata* new_metadata = CreateAudioMetadata();
  RTCEncodedAudioFrameOptions* frame_options =
      RTCEncodedAudioFrameOptions::Create();
  frame_options->setMetadata(new_metadata);

  RTCEncodedAudioFrame* new_frame = RTCEncodedAudioFrame::Create(
      encoded_frame, frame_options, exception_state);

  EXPECT_FALSE(exception_state.HadException()) << exception_state.Message();
  RTCEncodedAudioFrameMetadata* new_frame_metadata = new_frame->getMetadata();

  EXPECT_EQ(new_metadata->synchronizationSource(),
            new_frame_metadata->synchronizationSource());
  ASSERT_EQ(new_metadata->contributingSources().size(),
            new_frame_metadata->contributingSources().size());
  EXPECT_EQ(new_metadata->contributingSources()[0],
            new_frame_metadata->contributingSources()[0]);
  EXPECT_EQ(new_metadata->contributingSources()[1],
            new_frame_metadata->contributingSources()[1]);
  EXPECT_EQ(new_metadata->payloadType(), new_frame_metadata->payloadType());
  EXPECT_EQ(new_metadata->mimeType(), new_frame_metadata->mimeType());
  EXPECT_EQ(new_metadata->sequenceNumber(),
            new_frame_metadata->sequenceNumber());
  EXPECT_EQ(new_metadata->absCaptureTime(),
            new_frame_metadata->absCaptureTime());
  EXPECT_EQ(new_metadata->rtpTimestamp(), new_frame_metadata->rtpTimestamp());
}

TEST_F(RTCEncodedAudioFrameTest, ReadingDataOnEmptyFrameGivesDetachedFrame) {
  V8TestingScope v8_scope;

  std::unique_ptr<MockTransformableAudioFrame> frame =
      std::make_unique<NiceMock<MockTransformableAudioFrame>>();
  MockMetadata(frame.get());

  EXPECT_CALL(*frame, SetRTPTimestamp(_)).Times(0);

  RTCEncodedAudioFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedAudioFrame>(std::move(frame));
  encoded_frame->PassWebRtcFrame(v8_scope.GetIsolate(),
                                 /*detach_frame_data=*/false);

  DOMArrayBuffer* data = encoded_frame->data(v8_scope.GetExecutionContext());
  EXPECT_NE(data, nullptr);
  EXPECT_TRUE(data->IsDetached());
}

TEST_F(RTCEncodedAudioFrameTest, PassWebRTCDetachesFrameData) {
  V8TestingScope v8_scope;

  std::unique_ptr<MockTransformableAudioFrame> frame =
      std::make_unique<NiceMock<MockTransformableAudioFrame>>();
  MockMetadata(frame.get());

  EXPECT_CALL(*frame, SetRTPTimestamp(_)).Times(0);

  RTCEncodedAudioFrame* encoded_frame =
      MakeGarbageCollected<RTCEncodedAudioFrame>(std::move(frame));
  DOMArrayBuffer* data = encoded_frame->data(v8_scope.GetExecutionContext());
  encoded_frame->PassWebRtcFrame(v8_scope.GetIsolate(),
                                 /*detach_frame_data=*/true);
  EXPECT_NE(data, nullptr);
  EXPECT_TRUE(data->IsDetached());
}

}  // namespace blink

"""

```