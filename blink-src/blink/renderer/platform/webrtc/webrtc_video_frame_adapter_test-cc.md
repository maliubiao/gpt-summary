Response:
The user wants to understand the functionality of the C++ source code file `webrtc_video_frame_adapter_test.cc`. I need to analyze the code and identify its purpose. It's a test file, so its primary function is to test the behavior of the `WebRtcVideoFrameAdapter` class.

Here's a breakdown of the steps to address the user's request:

1. **Identify the core functionality:** The code defines several `TEST` functions. Each test focuses on a specific aspect of the `WebRtcVideoFrameAdapter`'s behavior, specifically related to scaling and cropping of video frames.

2. **Explain the relationship to web technologies:**  `WebRtcVideoFrameAdapter` is part of the WebRTC implementation in Blink. WebRTC is directly related to JavaScript APIs used for real-time communication in web browsers. I need to explain how the frame adaptation relates to what a web developer might do with video streams.

3. **Provide logical reasoning examples:** For tests involving cropping and scaling, I can provide the initial frame dimensions and the applied transformations, then predict the resulting dimensions. This demonstrates the relative nature of these operations.

4. **Illustrate common usage errors:**  While this is a test file, the tests themselves demonstrate the expected behavior of the adapter. I can infer potential user errors by considering what could go wrong if a developer were to implement similar logic in JavaScript or manipulate video streams. Incorrect size calculations or misunderstandings about relative cropping/scaling are good examples.

5. **Address the specific test cases:**  I need to explain what each individual test (`ScaledBufferSizeTest`, `WebRtcVideoFrameAdapterTest`) aims to verify. This includes concepts like zero-copy mapping and scaling from previously scaled frames.

6. **Structure the answer:** Organize the information logically, starting with the main functionality and then drilling down into specifics, including the connections to web technologies, examples, and potential errors.
这个C++源代码文件 `webrtc_video_frame_adapter_test.cc` 是 Chromium Blink 引擎中用于测试 `WebRtcVideoFrameAdapter` 类的单元测试文件。它的主要功能是验证 `WebRtcVideoFrameAdapter` 在处理视频帧时的各种操作，特别是关于裁剪（cropping）和缩放（scaling）的功能是否按预期工作。

**文件功能概述:**

1. **测试 `ScaledBufferSize` 结构:** 这个结构体可能用于表示视频帧的尺寸信息，包括可见区域和自然尺寸。测试用例验证了对 `ScaledBufferSize` 进行裁剪和缩放操作时的相对性，即连续的裁剪和缩放是相对于前一次操作的结果进行的。
2. **测试 `WebRtcVideoFrameAdapter` 的帧映射 (mapping) 功能:**  测试了将 `media::VideoFrame` 适配到 WebRTC 的 `webrtc::VideoFrameBuffer` 的过程。包括：
    * **零拷贝映射:**  验证当请求整个原始帧时，映射操作是否是零拷贝的，避免不必要的内存复制。
    * **创建新的缩放帧:** 验证当请求缩放后的帧时，`WebRtcVideoFrameAdapter` 是否能够创建新的 `webrtc::VideoFrameBuffer`。
    * **从最近的已缩放帧进行缩放:** 验证当需要进行多次缩放时，`WebRtcVideoFrameAdapter` 是否能够从最近一次已缩放的帧进行缩放，以提高效率。
    * **裁剪对缩放的影响:**  验证裁剪操作如何影响后续的缩放操作。
3. **测试帧反馈 (frame feedback) 机制:** 验证 `WebRtcVideoFrameAdapter` 是否能够根据是否进行了帧映射来设置反馈信息。

**与 JavaScript, HTML, CSS 的关系:**

虽然这是一个 C++ 测试文件，它所测试的 `WebRtcVideoFrameAdapter` 类是 WebRTC 实现的关键部分，而 WebRTC 是一项允许在浏览器中进行实时音视频通信的技术，它直接与 JavaScript API 相关。

* **JavaScript:**  JavaScript 代码可以使用 WebRTC API（例如 `getUserMedia`, `RTCPeerConnection`）来获取和处理音视频流。`WebRtcVideoFrameAdapter` 的作用是将底层的视频帧数据（通常是 C++ 对象 `media::VideoFrame`）适配成 WebRTC 可以直接使用的 `webrtc::VideoFrame` 对象。当 JavaScript 代码接收或发送视频帧时，Blink 引擎会使用类似 `WebRtcVideoFrameAdapter` 的组件来处理帧数据的转换和操作。例如，JavaScript 代码可能会请求缩放视频轨道以适应不同的显示尺寸或网络条件，这可能涉及到 `WebRtcVideoFrameAdapter` 的缩放功能。

    **举例说明:**

    ```javascript
    navigator.mediaDevices.getUserMedia({ video: true })
      .then(function(stream) {
        const videoTrack = stream.getVideoTracks()[0];
        const sender = peerConnection.addTrack(videoTrack, stream);

        // ... 假设需要将视频帧缩放到 640x360 ...
        const videoSettings = videoTrack.getSettings();
        // 浏览器底层可能会使用 WebRtcVideoFrameAdapter 来实现这种缩放
        // 以便在网络上传输或本地显示。
      });
    ```

* **HTML:** HTML 的 `<video>` 元素用于显示视频。WebRTC 获取的视频流最终可能会渲染到 `<video>` 元素中。`WebRtcVideoFrameAdapter` 处理的视频帧是最终显示在 HTML 页面上的内容的基础。

* **CSS:** CSS 可以控制 `<video>` 元素的显示尺寸和样式，但这通常是在已经处理好的视频帧上进行的。`WebRtcVideoFrameAdapter` 的缩放功能可能在 CSS 调整尺寸之前或之后发生，具体取决于实现和需求。例如，如果需要节省带宽，可能会先在底层使用 `WebRtcVideoFrameAdapter` 缩放视频帧，然后再使用 CSS 调整 `<video>` 元素的显示大小。

**逻辑推理的假设输入与输出:**

以下是一些基于测试用例的逻辑推理示例：

**测试用例: `ScaledBufferSizeTest.CroppingIsRelative`**

* **假设输入:**
    * 原始 `ScaledBufferSize`: 可见区域 (0, 0, 1280, 720)，自然尺寸 (1280, 720)
    * 第一次裁剪和缩放: 裁剪偏移 (100, 100)，裁剪尺寸 (1080, 520)，缩放尺寸 (1080, 520)
    * 第二次裁剪和缩放: 裁剪偏移 (100, 100)，裁剪尺寸 (880, 320)，缩放尺寸 (880, 320)
* **预期输出:**
    * 第一次裁剪和缩放后的 `ScaledBufferSize`: 可见区域 (100, 100, 1080, 520)，自然尺寸 (1080, 520)
    * 第二次裁剪和缩放后的 `ScaledBufferSize`: 可见区域 (200, 200, 880, 320)，自然尺寸 (880, 320)
* **推理:** 第二次裁剪是相对于第一次裁剪的结果进行的，所以偏移量和尺寸是累加和减去的。

**测试用例: `ScaledBufferSizeTest.ScalingIsRelative`**

* **假设输入:**
    * 原始 `ScaledBufferSize`: 可见区域 (0, 0, 1280, 720)，自然尺寸 (1280, 720)
    * 第一次缩放: 裁剪偏移 (0, 0)，裁剪尺寸 (1280, 720)，缩放尺寸 (640, 360)
    * 第二次缩放: 裁剪偏移 (0, 0)，裁剪尺寸 (640, 360)，缩放尺寸 (320, 180)
* **预期输出:**
    * 第一次缩放后的 `ScaledBufferSize`: 可见区域 (0, 0, 1280, 720)，自然尺寸 (640, 360)
    * 第二次缩放后的 `ScaledBufferSize`: 可见区域 (0, 0, 1280, 720)，自然尺寸 (320, 180)
* **推理:** 缩放操作会改变自然尺寸，而可见区域保持不变（除非显式指定裁剪）。第二次缩放是相对于第一次缩放后的自然尺寸进行的。

**用户或编程常见的使用错误举例说明:**

1. **误解裁剪的相对性:** 开发者可能错误地认为每次裁剪都是相对于原始帧进行的，而忽略了 `WebRtcVideoFrameAdapter` 的裁剪是相对的。

    * **错误示例 (假设在 JavaScript 中进行类似操作):**  如果开发者尝试连续裁剪一个视频帧，可能会错误地使用相对于原始尺寸的偏移量，而不是相对于上一次裁剪后尺寸的偏移量。

2. **不正确的缩放比例计算:** 开发者在请求缩放时，可能会错误地计算目标尺寸，导致视频显示失真或模糊。

    * **错误示例:**  假设原始帧是 1280x720，开发者想缩放到 640x360，但错误地计算为 640x480，导致宽高比不正确。

3. **过度或不必要的内存拷贝:**  如果不理解零拷贝映射的概念，开发者可能会在不需要的情况下手动复制视频帧数据，导致性能下降。`WebRtcVideoFrameAdapter` 旨在优化这种情况，但在某些操作下仍然会创建新的帧缓冲区。

4. **在不合适的时机进行裁剪和缩放:**  开发者可能在视频处理流程的错误阶段进行裁剪和缩放操作，例如在编码或解码之后，这可能会影响视频质量或效率。

5. **忘记考虑设备的硬件能力:**  某些设备可能对视频处理能力有限制。开发者可能会请求过于复杂的裁剪或缩放操作，导致性能问题。

总而言之，`webrtc_video_frame_adapter_test.cc` 通过各种测试用例，详细验证了 `WebRtcVideoFrameAdapter` 在处理视频帧时的核心功能，确保其能够正确地进行裁剪、缩放和映射操作，这对于 WebRTC 音视频通信的质量和性能至关重要。理解这些测试用例有助于开发者更好地理解 `WebRtcVideoFrameAdapter` 的工作原理，并避免在使用 WebRTC 相关功能时出现常见的错误。

Prompt: 
```
这是目录为blink/renderer/platform/webrtc/webrtc_video_frame_adapter_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/webrtc/webrtc_video_frame_adapter.h"

#include "base/memory/scoped_refptr.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/testing/video_frame_utils.h"
#include "third_party/blink/renderer/platform/webrtc/testing/mock_webrtc_video_frame_adapter_shared_resources.h"
#include "third_party/webrtc/api/scoped_refptr.h"
#include "third_party/webrtc/rtc_base/ref_counted_object.h"

namespace blink {

using ::testing::ElementsAre;
using ::testing::IsEmpty;

TEST(ScaledBufferSizeTest, CroppingIsRelative) {
  const WebRtcVideoFrameAdapter::ScaledBufferSize k720p(
      gfx::Rect(0, 0, 1280, 720), gfx::Size(1280, 720));

  // Crop away a 100 pixel border.
  const auto cropped_full_scale =
      k720p.CropAndScale(100, 100, 1080, 520, 1080, 520);
  EXPECT_EQ(cropped_full_scale.visible_rect.x(), 100);
  EXPECT_EQ(cropped_full_scale.visible_rect.y(), 100);
  EXPECT_EQ(cropped_full_scale.visible_rect.width(), 1080);
  EXPECT_EQ(cropped_full_scale.visible_rect.height(), 520);
  EXPECT_EQ(cropped_full_scale.natural_size.width(), 1080);
  EXPECT_EQ(cropped_full_scale.natural_size.height(), 520);

  // Applying the same size again should be a NO-OP.
  const auto cropped_full_scale2 =
      cropped_full_scale.CropAndScale(0, 0, 1080, 520, 1080, 520);
  EXPECT_TRUE(cropped_full_scale2 == cropped_full_scale);

  // Cropping again is relative to the current crop. Crop on crop.
  const auto second_cropped_full_size =
      cropped_full_scale.CropAndScale(100, 100, 880, 320, 880, 320);
  EXPECT_EQ(second_cropped_full_size.visible_rect.x(), 200);
  EXPECT_EQ(second_cropped_full_size.visible_rect.y(), 200);
  EXPECT_EQ(second_cropped_full_size.visible_rect.width(), 880);
  EXPECT_EQ(second_cropped_full_size.visible_rect.height(), 320);
  EXPECT_EQ(second_cropped_full_size.natural_size.width(), 880);
  EXPECT_EQ(second_cropped_full_size.natural_size.height(), 320);

  // Applying the same size again should be a NO-OP.
  const auto second_cropped_full_size2 =
      second_cropped_full_size.CropAndScale(0, 0, 880, 320, 880, 320);
  EXPECT_TRUE(second_cropped_full_size2 == second_cropped_full_size);

  // Cropping again is relative to the current crop. Crop on crop on crop.
  const auto third_cropped_full_size =
      second_cropped_full_size.CropAndScale(100, 100, 680, 120, 680, 120);
  EXPECT_EQ(third_cropped_full_size.visible_rect.x(), 300);
  EXPECT_EQ(third_cropped_full_size.visible_rect.y(), 300);
  EXPECT_EQ(third_cropped_full_size.visible_rect.width(), 680);
  EXPECT_EQ(third_cropped_full_size.visible_rect.height(), 120);
  EXPECT_EQ(third_cropped_full_size.natural_size.width(), 680);
  EXPECT_EQ(third_cropped_full_size.natural_size.height(), 120);
}

TEST(ScaledBufferSizeTest, ScalingIsRelative) {
  const WebRtcVideoFrameAdapter::ScaledBufferSize k720p(
      gfx::Rect(0, 0, 1280, 720), gfx::Size(1280, 720));

  // Scale down by 2x.
  const auto no_crop_half_size = k720p.CropAndScale(0, 0, 1280, 720, 640, 360);
  EXPECT_EQ(no_crop_half_size.visible_rect.x(), 0);
  EXPECT_EQ(no_crop_half_size.visible_rect.y(), 0);
  EXPECT_EQ(no_crop_half_size.visible_rect.width(), 1280);
  EXPECT_EQ(no_crop_half_size.visible_rect.height(), 720);
  EXPECT_EQ(no_crop_half_size.natural_size.width(), 640);
  EXPECT_EQ(no_crop_half_size.natural_size.height(), 360);

  // Applying the same size again should be a NO-OP.
  const auto no_crop_half_size2 =
      no_crop_half_size.CropAndScale(0, 0, 640, 360, 640, 360);
  EXPECT_TRUE(no_crop_half_size2 == no_crop_half_size);

  // Scaling again is relative to the current scale. Half-size on half-size.
  const auto no_crop_quarter_size =
      no_crop_half_size.CropAndScale(0, 0, 640, 360, 320, 180);
  EXPECT_EQ(no_crop_quarter_size.visible_rect.x(), 0);
  EXPECT_EQ(no_crop_quarter_size.visible_rect.y(), 0);
  EXPECT_EQ(no_crop_quarter_size.visible_rect.width(), 1280);
  EXPECT_EQ(no_crop_quarter_size.visible_rect.height(), 720);
  EXPECT_EQ(no_crop_quarter_size.natural_size.width(), 320);
  EXPECT_EQ(no_crop_quarter_size.natural_size.height(), 180);

  // Applying the same size again should be a NO-OP.
  const auto no_crop_quarter_size2 =
      no_crop_quarter_size.CropAndScale(0, 0, 320, 180, 320, 180);
  EXPECT_TRUE(no_crop_quarter_size2 == no_crop_quarter_size);

  // Scaling again is relative to the current scale.
  // Half-size on half-size on half-size.
  const auto no_crop_eighths_size =
      no_crop_quarter_size.CropAndScale(0, 0, 320, 180, 160, 90);
  EXPECT_EQ(no_crop_eighths_size.visible_rect.x(), 0);
  EXPECT_EQ(no_crop_eighths_size.visible_rect.y(), 0);
  EXPECT_EQ(no_crop_eighths_size.visible_rect.width(), 1280);
  EXPECT_EQ(no_crop_eighths_size.visible_rect.height(), 720);
  EXPECT_EQ(no_crop_eighths_size.natural_size.width(), 160);
  EXPECT_EQ(no_crop_eighths_size.natural_size.height(), 90);
}

TEST(ScaledBufferSizeTest, CroppingAndScalingIsRelative) {
  const WebRtcVideoFrameAdapter::ScaledBufferSize k720p(
      gfx::Rect(0, 0, 1280, 720), gfx::Size(1280, 720));

  // Crop away a 100 pixel border and downscale by 2x.
  const auto crop_and_scale1 =
      k720p.CropAndScale(100, 100, 1080, 520, 540, 260);
  EXPECT_EQ(crop_and_scale1.visible_rect.x(), 100);
  EXPECT_EQ(crop_and_scale1.visible_rect.y(), 100);
  EXPECT_EQ(crop_and_scale1.visible_rect.width(), 1080);
  EXPECT_EQ(crop_and_scale1.visible_rect.height(), 520);
  EXPECT_EQ(crop_and_scale1.natural_size.width(), 540);
  EXPECT_EQ(crop_and_scale1.natural_size.height(), 260);

  // Cropping some more at the new scale without further downscale.
  const auto crop_and_scale2 =
      crop_and_scale1.CropAndScale(50, 50, 440, 160, 440, 160);
  // The delta offset is magnified due to scale. Offset = 100*1 + 50*2.
  EXPECT_EQ(crop_and_scale2.visible_rect.x(), 200);
  EXPECT_EQ(crop_and_scale2.visible_rect.y(), 200);
  EXPECT_EQ(crop_and_scale2.visible_rect.width(), 880);
  EXPECT_EQ(crop_and_scale2.visible_rect.height(), 320);
  EXPECT_EQ(crop_and_scale2.natural_size.width(), 440);
  EXPECT_EQ(crop_and_scale2.natural_size.height(), 160);

  // Scaling some more without further cropping.
  const auto crop_and_scale3 =
      crop_and_scale2.CropAndScale(0, 0, 440, 160, 220, 80);
  EXPECT_EQ(crop_and_scale3.visible_rect.x(), 200);
  EXPECT_EQ(crop_and_scale3.visible_rect.y(), 200);
  EXPECT_EQ(crop_and_scale3.visible_rect.width(), 880);
  EXPECT_EQ(crop_and_scale3.visible_rect.height(), 320);
  EXPECT_EQ(crop_and_scale3.natural_size.width(), 220);
  EXPECT_EQ(crop_and_scale3.natural_size.height(), 80);
}

TEST(WebRtcVideoFrameAdapterTest, MapFullFrameIsZeroCopy) {
  std::vector<webrtc::VideoFrameBuffer::Type> kNv12 = {
      webrtc::VideoFrameBuffer::Type::kNV12};
  const gfx::Size kSize720p(1280, 720);
  const gfx::Rect kRect720p(0, 0, 1280, 720);

  // The strictness of the mock ensures zero copy.
  auto resources =
      base::MakeRefCounted<testing::StrictMock<MockSharedResources>>();

  auto frame_720p = CreateTestFrame(
      kSize720p, kRect720p, kSize720p, media::VideoFrame::STORAGE_OWNED_MEMORY,
      media::VideoPixelFormat::PIXEL_FORMAT_NV12, base::TimeDelta());

  rtc::scoped_refptr<WebRtcVideoFrameAdapter> multi_buffer(
      new rtc::RefCountedObject<WebRtcVideoFrameAdapter>(frame_720p,
                                                         resources));

  // Mapping produces a frame of the correct size.
  auto mapped_frame = multi_buffer->GetMappedFrameBuffer(kNv12);
  EXPECT_EQ(mapped_frame->width(), kSize720p.width());
  EXPECT_EQ(mapped_frame->height(), kSize720p.height());
  // The mapping above should be backed by |frame_720p|.
  auto adapted_frame = multi_buffer->GetAdaptedVideoBufferForTesting(
      WebRtcVideoFrameAdapter::ScaledBufferSize(kRect720p, kSize720p));
  EXPECT_EQ(adapted_frame, frame_720p);
}

TEST(WebRtcVideoFrameAdapterTest, MapScaledFrameCreatesNewFrame) {
  std::vector<webrtc::VideoFrameBuffer::Type> kNv12 = {
      webrtc::VideoFrameBuffer::Type::kNV12};
  const gfx::Size kSize720p(1280, 720);
  const gfx::Rect kRect720p(0, 0, 1280, 720);
  const gfx::Size kSize360p(640, 360);

  // Because the size we are going to request does not the frame we expect one
  // CreateFrame() to happen.
  auto resources =
      base::MakeRefCounted<testing::StrictMock<MockSharedResources>>();
  EXPECT_CALL(*resources, CreateFrame)
      .WillOnce(testing::Invoke(
          [](media::VideoPixelFormat format, const gfx::Size& coded_size,
             const gfx::Rect& visible_rect, const gfx::Size& natural_size,
             base::TimeDelta timestamp) {
            return CreateTestFrame(coded_size, visible_rect, natural_size,
                                   media::VideoFrame::STORAGE_OWNED_MEMORY,
                                   format, base::TimeDelta());
          }));
  resources->ExpectConvertAndScaleWithRealImplementation();

  auto frame_720p = CreateTestFrame(
      kSize720p, kRect720p, kSize720p, media::VideoFrame::STORAGE_OWNED_MEMORY,
      media::VideoPixelFormat::PIXEL_FORMAT_NV12, base::TimeDelta());

  rtc::scoped_refptr<WebRtcVideoFrameAdapter> multi_buffer(
      new rtc::RefCountedObject<WebRtcVideoFrameAdapter>(frame_720p,
                                                         resources));

  auto scaled_frame =
      multi_buffer->Scale(kSize360p.width(), kSize360p.height());

  // Mapping produces a frame of the correct size.
  auto mapped_frame = scaled_frame->GetMappedFrameBuffer(kNv12);
  EXPECT_EQ(mapped_frame->width(), kSize360p.width());
  EXPECT_EQ(mapped_frame->height(), kSize360p.height());
  // The mapping above should be backed by a frame that wraps |frame_720p|. We
  // can tell by looking at the coded size.
  auto adapted_frame = multi_buffer->GetAdaptedVideoBufferForTesting(
      WebRtcVideoFrameAdapter::ScaledBufferSize(kRect720p, kSize360p));
  ASSERT_TRUE(adapted_frame);
  EXPECT_EQ(adapted_frame->coded_size(), frame_720p->coded_size());
}

// When pre-scaled frames are not available we should scale from previously
// scaled frames. E.g. scaling 720p to 480p and then to 360p should perform
// scales "720p -> 480p" and "480p -> 360p" (NOT "720p -> 360p").
TEST(WebRtcVideoFrameAdapterTest,
     MapScaledFrameScalesFromClosestPreviouslyScaledFrameWithoutCropping) {
  std::vector<webrtc::VideoFrameBuffer::Type> kNv12 = {
      webrtc::VideoFrameBuffer::Type::kNV12};
  const gfx::Size kSize720p(1280, 720);
  const gfx::Rect kRect720p(0, 0, 1280, 720);
  const gfx::Size kSize480p(853, 480);
  const gfx::Size kSize360p(640, 360);

  auto resources =
      base::MakeRefCounted<testing::StrictMock<MockSharedResources>>();
  EXPECT_CALL(*resources, CreateFrame)
      .WillOnce(testing::Invoke(
          [](media::VideoPixelFormat format, const gfx::Size& coded_size,
             const gfx::Rect& visible_rect, const gfx::Size& natural_size,
             base::TimeDelta timestamp) {
            return CreateTestFrame(coded_size, visible_rect, natural_size,
                                   media::VideoFrame::STORAGE_OWNED_MEMORY,
                                   format, base::TimeDelta());
          }));
  resources->ExpectConvertAndScaleWithRealImplementation();

  auto frame_720p = CreateTestFrame(
      kSize720p, kRect720p, kSize720p, media::VideoFrame::STORAGE_OWNED_MEMORY,
      media::VideoPixelFormat::PIXEL_FORMAT_NV12, base::TimeDelta());

  rtc::scoped_refptr<WebRtcVideoFrameAdapter> multi_buffer(
      new rtc::RefCountedObject<WebRtcVideoFrameAdapter>(frame_720p,
                                                         resources));

  // Hard-apply scaling to 480p. Because a pre-scaled 480p is not available, we
  // scale from 720p.
  auto scaled_frame_480p =
      multi_buffer->Scale(kSize480p.width(), kSize480p.height());
  auto mapped_frame_480p = scaled_frame_480p->GetMappedFrameBuffer(kNv12);
  EXPECT_EQ(mapped_frame_480p->width(), kSize480p.width());
  EXPECT_EQ(mapped_frame_480p->height(), kSize480p.height());
  // The 480p must have been scaled from a media::VideoFrame.
  EXPECT_TRUE(multi_buffer->GetAdaptedVideoBufferForTesting(
      WebRtcVideoFrameAdapter::ScaledBufferSize(kRect720p, kSize480p)));
  // Hard-apply scaling to 360p. Because a pre-scaled 360p is not available, but
  // we did previously scale to 480p, the most efficient scale is 480p -> 360p.
  auto scaled_frame_360p =
      multi_buffer->Scale(kSize360p.width(), kSize360p.height());
  auto mapped_frame_360p = scaled_frame_360p->GetMappedFrameBuffer(kNv12);
  EXPECT_EQ(mapped_frame_360p->width(), kSize360p.width());
  EXPECT_EQ(mapped_frame_360p->height(), kSize360p.height());
  // The 360p should have gotten scaled from the previously mapped 480p frame,
  // so there should not be an associated media::VideoFrame here.
  EXPECT_FALSE(multi_buffer->GetAdaptedVideoBufferForTesting(
      WebRtcVideoFrameAdapter::ScaledBufferSize(kRect720p, kSize360p)));
}

TEST(WebRtcVideoFrameAdapterTest,
     MapScaledFrameScalesFromClosestPreviouslyScaledFrameWithCropping) {
  std::vector<webrtc::VideoFrameBuffer::Type> kNv12 = {
      webrtc::VideoFrameBuffer::Type::kNV12};
  const gfx::Size kFullCodedSize720p(1280, 720);
  const gfx::Rect kFullVisibleRect(20, 20, 1240, 680);  // 20 pixel border.
  const gfx::Size kFullNaturalSize(620, 340);           // Scaled down by 2.

  auto resources =
      base::MakeRefCounted<testing::StrictMock<MockSharedResources>>();
  EXPECT_CALL(*resources, CreateFrame)
      .WillOnce(testing::Invoke(
          [](media::VideoPixelFormat format, const gfx::Size& coded_size,
             const gfx::Rect& visible_rect, const gfx::Size& natural_size,
             base::TimeDelta timestamp) {
            return CreateTestFrame(coded_size, visible_rect, natural_size,
                                   media::VideoFrame::STORAGE_OWNED_MEMORY,
                                   format, base::TimeDelta());
          }));
  resources->ExpectConvertAndScaleWithRealImplementation();

  // Create a full frame with soft-applied cropping and scaling.
  auto full_frame = CreateTestFrame(
      kFullCodedSize720p, kFullVisibleRect, kFullNaturalSize,
      media::VideoFrame::STORAGE_OWNED_MEMORY,
      media::VideoPixelFormat::PIXEL_FORMAT_NV12, base::TimeDelta());

  rtc::scoped_refptr<WebRtcVideoFrameAdapter> multi_buffer(
      new rtc::RefCountedObject<WebRtcVideoFrameAdapter>(full_frame,
                                                         resources));

  // Crop and scale some more and then map it.
  // Apply a 10 pixel border and downscale by a factor of 2 again.
  auto scaled_frame = multi_buffer->CropAndScale(10, 10, 600, 320, 300, 160);
  auto mapped_scaled_frame = scaled_frame->GetMappedFrameBuffer(kNv12);
  gfx::Size kScaledFrameSize(300, 160);
  EXPECT_EQ(mapped_scaled_frame->width(), kScaledFrameSize.width());
  EXPECT_EQ(mapped_scaled_frame->height(), kScaledFrameSize.height());
  // The cropping above is magnified due to scaling factors.
  gfx::Rect kScaledFrameVisibleRect(kFullVisibleRect.x() + (10 * 2),
                                    kFullVisibleRect.y() + (10 * 2), (600 * 2),
                                    (320 * 2));
  EXPECT_TRUE(multi_buffer->GetAdaptedVideoBufferForTesting(
      WebRtcVideoFrameAdapter::ScaledBufferSize(kScaledFrameVisibleRect,
                                                kScaledFrameSize)));

  // Downscale by another factor of two.
  gfx::Size kTinyFrameSize(kScaledFrameSize.width() / 2,
                           kScaledFrameSize.height() / 2);
  auto tiny_frame =
      scaled_frame->Scale(kTinyFrameSize.width(), kTinyFrameSize.height());
  auto mapped_tiny_frame = tiny_frame->GetMappedFrameBuffer(kNv12);
  EXPECT_EQ(mapped_tiny_frame->width(), kTinyFrameSize.width());
  EXPECT_EQ(mapped_tiny_frame->height(), kTinyFrameSize.height());
  // Because we do not have any pre-scaled images, but we have mapped frames,
  // subsequent downscales should be based on the previous mappings rather than
  // the full frame.
  EXPECT_FALSE(multi_buffer->GetAdaptedVideoBufferForTesting(
      WebRtcVideoFrameAdapter::ScaledBufferSize(kScaledFrameVisibleRect,
                                                kTinyFrameSize)));
}

TEST(WebRtcVideoFrameAdapterTest,
     MapScaledFrameDoesNotScaleFromPreviouslyScaledFrameWithOtherCrop) {
  std::vector<webrtc::VideoFrameBuffer::Type> kNv12 = {
      webrtc::VideoFrameBuffer::Type::kNV12};
  const gfx::Size kSize720p(1280, 720);
  const gfx::Rect kRect720p(0, 0, 1280, 720);
  const gfx::Rect kCroppedRect(1272, 720);  // Crop only a few pixels.
  const gfx::Size kSize480p(853, 480);
  const gfx::Size kSize360p(640, 360);

  auto resources =
      base::MakeRefCounted<testing::StrictMock<MockSharedResources>>();
  EXPECT_CALL(*resources, CreateFrame)
      .Times(2)
      .WillRepeatedly(testing::Invoke(
          [](media::VideoPixelFormat format, const gfx::Size& coded_size,
             const gfx::Rect& visible_rect, const gfx::Size& natural_size,
             base::TimeDelta timestamp) {
            return CreateTestFrame(coded_size, visible_rect, natural_size,
                                   media::VideoFrame::STORAGE_OWNED_MEMORY,
                                   format, base::TimeDelta());
          }));

  auto frame_720p = CreateTestFrame(
      kSize720p, kRect720p, kSize720p, media::VideoFrame::STORAGE_OWNED_MEMORY,
      media::VideoPixelFormat::PIXEL_FORMAT_NV12, base::TimeDelta());

  rtc::scoped_refptr<WebRtcVideoFrameAdapter> multi_buffer(
      new rtc::RefCountedObject<WebRtcVideoFrameAdapter>(frame_720p,
                                                         resources));

  // Hard-apply scaling to 480p WITH cropping.
  resources->ExpectConvertAndScaleWithRealImplementation();
  auto scaled_frame_480p = multi_buffer->CropAndScale(
      kCroppedRect.x(), kCroppedRect.y(), kCroppedRect.width(),
      kCroppedRect.height(), kSize480p.width(), kSize480p.height());
  auto mapped_frame_480p = scaled_frame_480p->GetMappedFrameBuffer(kNv12);
  EXPECT_EQ(mapped_frame_480p->width(), kSize480p.width());
  EXPECT_EQ(mapped_frame_480p->height(), kSize480p.height());
  // The 480p must have been scaled from a media::VideoFrame.
  EXPECT_TRUE(multi_buffer->GetAdaptedVideoBufferForTesting(
      WebRtcVideoFrameAdapter::ScaledBufferSize(kCroppedRect, kSize480p)));

  // Hard-apply scaling to 360p WITHOUT cropping.
  resources->ExpectConvertAndScaleWithRealImplementation();
  auto scaled_frame_360p =
      multi_buffer->Scale(kSize360p.width(), kSize360p.height());
  auto mapped_frame_360p = scaled_frame_360p->GetMappedFrameBuffer(kNv12);
  EXPECT_EQ(mapped_frame_360p->width(), kSize360p.width());
  EXPECT_EQ(mapped_frame_360p->height(), kSize360p.height());
  // Because the previously mapped 480p buffer has cropping it cannot be used
  // for scaling, so 360p is produced from the 720p frame.
  EXPECT_TRUE(multi_buffer->GetAdaptedVideoBufferForTesting(
      WebRtcVideoFrameAdapter::ScaledBufferSize(kRect720p, kSize360p)));
}

TEST(WebRtcVideoFrameAdapterTest, FrameFeedbackSetsRequireMappedFrame) {
  std::vector<webrtc::VideoFrameBuffer::Type> kNv12 = {
      webrtc::VideoFrameBuffer::Type::kNV12};
  const gfx::Size kSize720p(1280, 720);
  const gfx::Rect kRect720p(0, 0, 1280, 720);
  const gfx::Size kSize360p(640, 360);

  scoped_refptr<WebRtcVideoFrameAdapter::SharedResources> resources =
      base::MakeRefCounted<WebRtcVideoFrameAdapter::SharedResources>(nullptr);

  auto frame_720p = CreateTestFrame(
      kSize720p, kRect720p, kSize720p, media::VideoFrame::STORAGE_OWNED_MEMORY,
      media::VideoPixelFormat::PIXEL_FORMAT_NV12, base::TimeDelta());

  // By default, the feedback is not set to require mapping.
  EXPECT_FALSE(resources->GetFeedback().require_mapped_frame);
  {
    // Do some scaling, but don't map it.
    rtc::scoped_refptr<WebRtcVideoFrameAdapter> multi_buffer(
        new rtc::RefCountedObject<WebRtcVideoFrameAdapter>(frame_720p,
                                                           resources));
    multi_buffer->Scale(kSize360p.width(), kSize360p.height());
  }
  EXPECT_FALSE(resources->GetFeedback().require_mapped_frame);
  {
    // Do map the buffer.
    rtc::scoped_refptr<WebRtcVideoFrameAdapter> multi_buffer(
        new rtc::RefCountedObject<WebRtcVideoFrameAdapter>(frame_720p,
                                                           resources));
    multi_buffer->Scale(kSize360p.width(), kSize360p.height())
        ->GetMappedFrameBuffer(kNv12);
  }
  EXPECT_TRUE(resources->GetFeedback().require_mapped_frame);
}

}  // namespace blink

"""

```