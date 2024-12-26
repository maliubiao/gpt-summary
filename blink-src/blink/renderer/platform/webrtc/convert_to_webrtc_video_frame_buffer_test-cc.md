Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The file name `convert_to_webrtc_video_frame_buffer_test.cc` immediately tells us this is a test file. The core functionality being tested is likely the `ConvertToWebRtcVideoFrameBuffer` function (or related logic). The goal of this function is probably to take a `media::VideoFrame` (a Chromium representation of a video frame) and convert it into a `webrtc::VideoFrameBuffer` (WebRTC's representation).

2. **Identify Key Components:**
    * **Headers:** The included headers reveal important dependencies:
        * `convert_to_webrtc_video_frame_buffer.h`: This is the header for the function being tested.
        * `media/base/video_frame.h`:  Deals with Chromium's `VideoFrame` object.
        * `third_party/webrtc/api/video/video_frame_buffer.h`: Deals with WebRTC's `VideoFrameBuffer` object.
        * `testing/gtest/include/gtest/gtest.h`:  Indicates Google Test is being used for testing.
        * `testing/gmock/include/gmock/gmock.h`: Indicates Google Mock is being used for mocking dependencies.
        * Other headers like `base/memory/scoped_refptr.h`, `base/strings/strcat.h`, etc., are common utility headers.
    * **Namespaces:** The code uses the `blink` namespace, confirming it's part of the Chromium Blink rendering engine. It also uses the anonymous namespace for internal helper functions.
    * **Test Fixtures:**  The `ConvertToWebRtcVideoFrameBufferParamTest` class uses `::testing::TestWithParam`. This signals parameterized testing, where the same test logic is run with different sets of input parameters.
    * **Test Cases:** The `TEST_P` and `TEST` macros indicate individual test cases.
    * **Helper Functions:** The `TestParams()` function clearly sets up the parameter values for the parameterized test. The `CreateTestFrame` function (from `video_frame_utils.h`) is a utility to generate test `media::VideoFrame` objects.
    * **Mocking:** The `MockSharedResources` class (from `mock_webrtc_video_frame_adapter_shared_resources.h`) indicates that dependencies are being mocked for certain test scenarios.

3. **Analyze Test Cases (Iterative Process):** Go through each test case and understand what it's verifying:

    * **`ConvertToWebRtcVideoFrameBufferParamTest`, `ToI420`:**  This parameterized test checks the conversion of various `media::VideoFrame` storage types and pixel formats to WebRTC's I420 format. It verifies the output `VideoFrameBuffer` has the correct dimensions (natural size).
    * **`ConvertToWebRtcVideoFrameBufferTest`, `ToI420ADownScale`:** Tests the conversion of an I420A frame (with an alpha channel) and verifies the output `VideoFrameBuffer` and its I420 representation have the correct natural size.
    * **`Nv12WrapsGmbWhenNoScalingNeeededWithFeature`:** Tests the case where a GPU memory buffer (GMB) backed NV12 frame is converted, and no scaling is needed. It verifies that the resulting `VideoFrameBuffer` directly wraps the GMB (is also NV12) and has the correct dimensions. It also checks that `ToI420` still produces an I420 frame.
    * **`Nv12ScalesGmbWithFeature`:** Similar to the previous test, but with scaling involved (natural size is different from visible rect). It verifies that the output `VideoFrameBuffer` is NV12 with the correct natural size.
    * **`Nv12OwnedMemoryFrame`:** Tests the conversion of an owned-memory NV12 frame without scaling. It verifies that the output `VideoFrameBuffer` is NV12 with the visible rectangle's size.
    * **`Nv12ScaleOwnedMemoryFrame`:** Tests the conversion of an owned-memory NV12 frame with scaling. It verifies that the output `VideoFrameBuffer` is NV12 with the natural size.
    * **`TextureFrameIsBlackWithNoSharedResources`:** Tests the conversion of a texture-backed frame when no `SharedResources` object is provided. It expects the resulting I420 frame to be black (all luma set to 0, chroma to 128). This highlights a dependency on `SharedResources` for texture handling.
    * **`ConvertsTextureFrameWithSharedResources`:** Tests the conversion of a texture-backed frame *with* a `SharedResources` object (which is mocked). It verifies that the conversion logic is invoked (mock calls are made) and that the resulting I420 frame is *not* black, indicating successful texture conversion.

4. **Identify Relationships to Web Technologies:**

    * **WebRTC:** The core purpose of this code is to bridge the gap between Chromium's internal video frame representation and WebRTC's. WebRTC is directly related to JavaScript APIs for real-time communication (e.g., `getUserMedia`, `RTCPeerConnection`).
    * **HTML `<video>` Element:**  Video frames processed by this code might originate from or be displayed in an HTML `<video>` element.
    * **Canvas API:** The Canvas API can be used to manipulate video frames, and those frames might need to be converted for WebRTC.
    * **CSS:** CSS might affect the *display* of the video, but it doesn't directly interact with the frame *conversion* process. However, the reported `naturalSize` can influence how the video is rendered according to CSS rules.

5. **Look for Logic and Assumptions:**

    * **Scaling Logic:** The tests implicitly demonstrate assumptions about how scaling is handled for different storage types (GMB vs. owned memory) and pixel formats. The tests verify that the output dimensions match the expected natural size after scaling.
    * **Texture Handling:** The tests clearly show that converting texture-backed frames requires `SharedResources`. Without it, the output is a black frame.
    * **Pixel Format Conversion:** The tests involving `ToI420` verify that the conversion to this common format is happening correctly.
    * **Parameterization:** The use of `TestWithParam` is a key logical element, allowing for testing multiple scenarios with the same test logic.

6. **Consider Potential User/Programming Errors:**

    * **Missing `SharedResources`:** The test case for texture frames without `SharedResources` directly highlights a potential error. If a developer tries to use a texture frame with WebRTC without providing the necessary resources, they'll likely get unexpected black frames.
    * **Incorrect Size Assumptions:**  The tests verify that the reported width and height of the `VideoFrameBuffer` match the `naturalSize`. A developer might mistakenly assume the dimensions will always match the coded size or visible rect, leading to issues if they rely on those incorrect dimensions in their application.
    * **Forgetting to Handle Different Storage Types:** The parameterized tests emphasize the importance of handling different `media::VideoFrame::StorageType` values correctly. A developer might only test with owned memory and then encounter problems when dealing with GMB-backed frames.

7. **Review and Refine:**  After the initial analysis, reread the code and the notes. Are there any ambiguities?  Have all the key aspects been covered?  Ensure the explanations are clear and concise. For example, explicitly mentioning the mapping between `naturalSize` and WebRTC's reported dimensions is crucial.

This systematic approach, moving from the general purpose of the file to the specifics of each test case and then connecting those specifics to broader concepts, allows for a comprehensive understanding of the code's functionality and its implications.
这个C++源代码文件 `convert_to_webrtc_video_frame_buffer_test.cc` 的主要功能是**测试将 Chromium 的 `media::VideoFrame` 对象转换为 WebRTC 的 `webrtc::VideoFrameBuffer` 对象的功能。**  具体来说，它测试了 `ConvertToWebRtcVideoFrameBuffer` 函数在各种不同输入条件下的正确性。

让我们更详细地分解其功能以及与 Web 技术的关系：

**1. 功能列表:**

* **测试 `ConvertToWebRtcVideoFrameBuffer` 函数:** 这是核心功能。该文件通过各种测试用例验证了 `ConvertToWebRtcVideoFrameBuffer` 函数是否能正确地将 Chromium 的视频帧转换为 WebRTC 可以理解的格式。
* **覆盖不同的视频帧存储类型:** 测试了不同类型的 `media::VideoFrame` 的存储方式，例如：
    * `STORAGE_OWNED_MEMORY`: 视频数据存储在由 `media::VideoFrame` 对象拥有的内存中。
    * `STORAGE_GPU_MEMORY_BUFFER`: 视频数据存储在 GPU 内存缓冲区中。
    * `STORAGE_OPAQUE`:  视频数据由纹理等底层图形资源支持。
* **覆盖不同的像素格式:** 测试了不同的视频像素格式，例如：
    * `PIXEL_FORMAT_I420`: 一种常见的亮度-色度色彩空间。
    * `PIXEL_FORMAT_NV12`: 另一种常见的亮度-色度色彩空间，在硬件加速中常用。
    * `PIXEL_FORMAT_I420A`:  I420 格式，带有 Alpha 通道。
* **测试缩放场景:**  测试了当视频帧的自然尺寸 (natural size) 与可见矩形 (visible rect) 不同时，转换后的 `webrtc::VideoFrameBuffer` 的尺寸是否正确。
* **测试使用和不使用共享资源的情况:**  对于纹理类型的视频帧，测试了在有和没有 `WebRtcVideoFrameAdapter::SharedResources` 的情况下转换的行为。
* **使用 Google Test 框架进行测试:**  利用 `TEST_P` 和 `TEST` 宏定义不同的测试用例，并使用 `EXPECT_EQ` 等断言来验证结果。
* **使用 Google Mock 框架进行模拟:**  使用 `MockSharedResources` 来模拟 `WebRtcVideoFrameAdapter::SharedResources` 的行为，以便隔离测试纹理帧转换的逻辑。

**2. 与 JavaScript, HTML, CSS 的关系:**

这个 C++ 文件本身不包含 JavaScript, HTML, 或 CSS 代码。然而，它所测试的功能是 WebRTC 技术栈的关键部分，而 WebRTC 技术栈是 Web 平台的一部分，允许在浏览器中实现实时音视频通信。

* **JavaScript:**
    * **`getUserMedia()` API:**  JavaScript 代码可以使用 `getUserMedia()` API 来获取用户的摄像头或麦克风的媒体流。  这个媒体流产生的视频帧最终会以 `media::VideoFrame` 的形式传递到 Blink 引擎。 `ConvertToWebRtcVideoFrameBuffer` 的功能就是将这些 Chromium 的视频帧转换为 WebRTC 内部可以处理的格式，以便通过网络发送给其他对等端。
    * **`RTCPeerConnection` API:**  一旦视频帧被转换为 `webrtc::VideoFrameBuffer`，它就可以被 `RTCPeerConnection` API 使用，通过网络发送到另一个浏览器或应用程序。
    * **假设输入与输出 (逻辑推理):**
        * **假设输入 (JavaScript):** 用户通过 `getUserMedia()` 获取了摄像头视频流，该视频流的帧率为 30fps，分辨率为 640x480。
        * **假设输出 (C++ 侧):**  `ConvertToWebRtcVideoFrameBuffer` 函数接收到相应的 `media::VideoFrame` 对象，并将其转换为 `webrtc::VideoFrameBuffer` 对象。这个 `webrtc::VideoFrameBuffer` 对象将包含与原始帧相同的数据（可能经过格式转换，例如转换为 I420），并可以被 WebRTC 的其他组件处理。

* **HTML:**
    * **`<video>` 标签:**  通过 WebRTC 接收到的远程视频流最终会被渲染到 HTML 的 `<video>` 标签中进行显示。  `ConvertToWebRtcVideoFrameBuffer` 确保了发送出去的视频帧是符合 WebRTC 标准的格式，以便接收端能够解码和显示。

* **CSS:**
    * **视频样式:** CSS 可以用来控制 `<video>` 标签的样式，例如大小、边框等。虽然 CSS 不直接参与视频帧的转换，但转换后的视频帧的尺寸会影响 CSS 的布局和渲染效果。  例如，如果 `ConvertToWebRtcVideoFrameBuffer` 没有正确处理缩放，那么显示在 `<video>` 标签中的视频可能会变形或显示不完整。

**3. 逻辑推理与假设输入/输出:**

我们已经稍微涉及了逻辑推理，让我们更具体地看一个测试用例：

* **测试用例:** `TEST_P(ConvertToWebRtcVideoFrameBufferParamTest, ToI420)`
* **假设输入:**
    * 一个 `media::VideoFrame` 对象，其存储类型为 `STORAGE_OWNED_MEMORY`，像素格式为 `PIXEL_FORMAT_NV12`，编码尺寸为 1280x960，可见矩形为 (0, 120, 1280, 720)，自然尺寸为 640x360。
    * 一个 `WebRtcVideoFrameAdapter::SharedResources` 对象。
* **执行的逻辑:** `ConvertToWebRtcVideoFrameBuffer` 函数被调用，将输入的 `media::VideoFrame` 转换为 `webrtc::VideoFrameBuffer`。然后，调用 `ToI420()` 方法将结果转换为 I420 格式的缓冲区。
* **预期输出:**
    * 转换后的 `webrtc::VideoFrameBuffer` 对象的宽度应等于自然尺寸的宽度 (640)。
    * 转换后的 `webrtc::VideoFrameBuffer` 对象的高度应等于自然尺寸的高度 (360)。
    * 调用 `ToI420()` 得到的 I420 缓冲区的宽度应为 640，高度应为 360。

**4. 用户或编程常见的使用错误:**

* **未提供 `SharedResources` 处理纹理帧:**  `TEST(ConvertToWebRtcVideoFrameBufferTest, TextureFrameIsBlackWithNoSharedResources)` 这个测试用例就演示了一个常见错误。如果开发者试图将一个基于纹理的 `media::VideoFrame` 转换为 WebRTC 的 `VideoFrameBuffer`，但没有提供有效的 `SharedResources` 对象，那么转换后的帧内容可能是不可预测的（在这个测试中被断言为黑色）。这会导致远端接收到的视频出现问题。
* **对视频帧尺寸的错误假设:**  开发者可能会错误地认为转换后的 WebRTC 视频帧的尺寸总是与原始 `media::VideoFrame` 的编码尺寸或可见矩形相同。但实际上，`ConvertToWebRtcVideoFrameBuffer` 通常会使用自然尺寸作为 WebRTC 帧的尺寸。如果开发者基于错误的尺寸假设进行后续处理，可能会导致布局或显示问题。
* **不支持的像素格式:** 虽然该测试文件覆盖了一些常见的像素格式，但可能存在 `ConvertToWebRtcVideoFrameBuffer` 函数不支持的像素格式。如果开发者尝试转换不支持的格式，可能会导致转换失败或产生意外的结果。
* **资源管理错误:** `media::VideoFrame` 和 `webrtc::VideoFrameBuffer` 都涉及到内存管理。开发者需要确保正确地管理这些对象的生命周期，避免内存泄漏或其他资源管理问题。例如，如果 `media::VideoFrame` 在转换过程中被错误地释放，可能会导致程序崩溃。

总而言之，`convert_to_webrtc_video_frame_buffer_test.cc` 是一个至关重要的测试文件，它确保了 Chromium 的视频处理管道能够正确地将视频帧转换为 WebRTC 可以使用的格式，这是 WebRTC 功能正常运行的基础，直接影响着基于 WebRTC 的音视频通信应用的质量和稳定性。

Prompt: 
```
这是目录为blink/renderer/platform/webrtc/convert_to_webrtc_video_frame_buffer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/webrtc/convert_to_webrtc_video_frame_buffer.h"

#include "base/memory/scoped_refptr.h"
#include "base/strings/strcat.h"
#include "media/base/video_frame.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/testing/video_frame_utils.h"
#include "third_party/blink/renderer/platform/webrtc/testing/mock_webrtc_video_frame_adapter_shared_resources.h"
#include "third_party/blink/renderer/platform/webrtc/webrtc_video_frame_adapter.h"
#include "third_party/webrtc/api/video/video_frame_buffer.h"
#include "third_party/webrtc/rtc_base/ref_counted_object.h"
#include "ui/gfx/gpu_memory_buffer.h"

using ::testing::_;
using ::testing::Return;

namespace blink {

class ConvertToWebRtcVideoFrameBufferParamTest
    : public ::testing::TestWithParam<
          std::tuple<media::VideoFrame::StorageType, media::VideoPixelFormat>> {
 protected:
  scoped_refptr<WebRtcVideoFrameAdapter::SharedResources> resources_ =
      base::MakeRefCounted<WebRtcVideoFrameAdapter::SharedResources>(nullptr);
};

namespace {
std::vector<ConvertToWebRtcVideoFrameBufferParamTest::ParamType> TestParams() {
  std::vector<ConvertToWebRtcVideoFrameBufferParamTest::ParamType> test_params;
  // All formats for owned memory.
  for (media::VideoPixelFormat format :
       GetPixelFormatsMappableToWebRtcVideoFrameBuffer()) {
    test_params.emplace_back(
        media::VideoFrame::StorageType::STORAGE_OWNED_MEMORY, format);
  }
  test_params.emplace_back(
      media::VideoFrame::StorageType::STORAGE_GPU_MEMORY_BUFFER,
      media::VideoPixelFormat::PIXEL_FORMAT_NV12);
  return test_params;
}
}  // namespace

TEST_P(ConvertToWebRtcVideoFrameBufferParamTest, ToI420) {
  const gfx::Size kCodedSize(1280, 960);
  const gfx::Rect kVisibleRect(0, 120, 1280, 720);
  const gfx::Size kNaturalSize(640, 360);

  media::VideoFrame::StorageType storage_type = std::get<0>(GetParam());
  media::VideoPixelFormat pixel_format = std::get<1>(GetParam());
  scoped_refptr<media::VideoFrame> frame =
      CreateTestFrame(kCodedSize, kVisibleRect, kNaturalSize, storage_type,
                      pixel_format, base::TimeDelta());
  rtc::scoped_refptr<webrtc::VideoFrameBuffer> frame_buffer =
      ConvertToWebRtcVideoFrameBuffer(std::move(frame), resources_);

  // The I420 frame should have the same size as the natural size.
  auto i420_frame = frame_buffer->ToI420();
  EXPECT_EQ(i420_frame->width(), kNaturalSize.width());
  EXPECT_EQ(i420_frame->height(), kNaturalSize.height());
}

INSTANTIATE_TEST_SUITE_P(
    ConvertToWebRtcVideoFrameBufferParamTest,
    ConvertToWebRtcVideoFrameBufferParamTest,
    ::testing::ValuesIn(TestParams()),
    [](const auto& info) {
      return base::StrCat(
          {media::VideoFrame::StorageTypeToString(std::get<0>(info.param)), "_",
           media::VideoPixelFormatToString(std::get<1>(info.param))});
    });

TEST(ConvertToWebRtcVideoFrameBufferTest, ToI420ADownScale) {
  const gfx::Size kCodedSize(1280, 960);
  const gfx::Rect kVisibleRect(0, 120, 1280, 720);
  const gfx::Size kNaturalSize(640, 360);
  auto resources =
      base::MakeRefCounted<WebRtcVideoFrameAdapter::SharedResources>(nullptr);

  // The adapter should report width and height from the natural size for
  // VideoFrame backed by owned memory.
  auto owned_memory_frame = CreateTestFrame(
      kCodedSize, kVisibleRect, kNaturalSize,
      media::VideoFrame::STORAGE_OWNED_MEMORY,
      media::VideoPixelFormat::PIXEL_FORMAT_I420A, base::TimeDelta());
  rtc::scoped_refptr<webrtc::VideoFrameBuffer> owned_memory_frame_buffer =
      ConvertToWebRtcVideoFrameBuffer(std::move(owned_memory_frame), resources);
  EXPECT_EQ(owned_memory_frame_buffer->width(), kNaturalSize.width());
  EXPECT_EQ(owned_memory_frame_buffer->height(), kNaturalSize.height());

  // The I420A frame should have the same size as the natural size
  auto i420a_frame = owned_memory_frame_buffer->ToI420();
  ASSERT_TRUE(i420a_frame);
  EXPECT_EQ(webrtc::VideoFrameBuffer::Type::kI420A, i420a_frame->type());
  EXPECT_EQ(i420a_frame->width(), kNaturalSize.width());
  EXPECT_EQ(i420a_frame->height(), kNaturalSize.height());
}

TEST(ConvertToWebRtcVideoFrameBufferTest,
     Nv12WrapsGmbWhenNoScalingNeeededWithFeature) {
  const gfx::Size kCodedSize(1280, 960);
  const gfx::Rect kVisibleRect(0, 120, 1280, 720);
  // Same size as visible rect so no scaling.
  const gfx::Size kNaturalSize = kVisibleRect.size();
  auto resources =
      base::MakeRefCounted<WebRtcVideoFrameAdapter::SharedResources>(nullptr);

  auto gmb_frame =
      CreateTestFrame(kCodedSize, kVisibleRect, kNaturalSize,
                      media::VideoFrame::STORAGE_GPU_MEMORY_BUFFER);

  // The adapter should report width and height from the natural size for
  // VideoFrame backed by GpuMemoryBuffer.
  rtc::scoped_refptr<webrtc::VideoFrameBuffer> gmb_frame_buffer =
      ConvertToWebRtcVideoFrameBuffer(std::move(gmb_frame), resources);
  EXPECT_EQ(gmb_frame_buffer->width(), kNaturalSize.width());
  EXPECT_EQ(gmb_frame_buffer->height(), kNaturalSize.height());

  // Under feature, expect that the adapted frame is NV12 with frame should
  // have the same size as the natural size.
  auto* nv12_frame = gmb_frame_buffer->GetNV12();
  ASSERT_TRUE(nv12_frame);
  EXPECT_EQ(webrtc::VideoFrameBuffer::Type::kNV12, nv12_frame->type());
  EXPECT_EQ(nv12_frame->width(), kNaturalSize.width());
  EXPECT_EQ(nv12_frame->height(), kNaturalSize.height());

  // Even though we have an NV12 frame, ToI420 should return an I420 frame.
  auto i420_frame = gmb_frame_buffer->ToI420();
  ASSERT_TRUE(i420_frame);
  EXPECT_EQ(i420_frame->width(), kNaturalSize.width());
  EXPECT_EQ(i420_frame->height(), kNaturalSize.height());
}

TEST(ConvertToWebRtcVideoFrameBufferTest, Nv12ScalesGmbWithFeature) {
  const gfx::Size kCodedSize(1280, 960);
  const gfx::Rect kVisibleRect(0, 120, 1280, 720);
  const gfx::Size kNaturalSize(640, 360);
  auto resources =
      base::MakeRefCounted<WebRtcVideoFrameAdapter::SharedResources>(nullptr);

  auto gmb_frame =
      CreateTestFrame(kCodedSize, kVisibleRect, kNaturalSize,
                      media::VideoFrame::STORAGE_GPU_MEMORY_BUFFER);

  // The adapter should report width and height from the natural size for
  // VideoFrame backed by GpuMemoryBuffer.
  rtc::scoped_refptr<webrtc::VideoFrameBuffer> gmb_frame_buffer =
      ConvertToWebRtcVideoFrameBuffer(gmb_frame, resources);
  EXPECT_EQ(gmb_frame_buffer->width(), kNaturalSize.width());
  EXPECT_EQ(gmb_frame_buffer->height(), kNaturalSize.height());

  // Under feature, expect that the adapted frame is NV12 with frame should
  // have the same size as the natural size.
  auto* nv12_frame = gmb_frame_buffer->GetNV12();
  ASSERT_TRUE(nv12_frame);
  EXPECT_EQ(webrtc::VideoFrameBuffer::Type::kNV12, nv12_frame->type());
  EXPECT_EQ(nv12_frame->width(), kNaturalSize.width());
  EXPECT_EQ(nv12_frame->height(), kNaturalSize.height());

  // Even though we have an NV12 frame, ToI420 should return an I420 frame.
  auto i420_frame = gmb_frame_buffer->ToI420();
  ASSERT_TRUE(i420_frame);
  EXPECT_EQ(i420_frame->width(), kNaturalSize.width());
  EXPECT_EQ(i420_frame->height(), kNaturalSize.height());
}

TEST(ConvertToWebRtcVideoFrameBufferTest, Nv12OwnedMemoryFrame) {
  const gfx::Size kCodedSize(1280, 960);
  const gfx::Rect kVisibleRect(0, 120, 1280, 720);
  const gfx::Size kNaturalSize = kVisibleRect.size();
  auto resources =
      base::MakeRefCounted<WebRtcVideoFrameAdapter::SharedResources>(nullptr);

  // The adapter should report width and height from the natural size for
  // VideoFrame backed by owned memory.
  auto owned_memory_frame = CreateTestFrame(
      kCodedSize, kVisibleRect, kNaturalSize,
      media::VideoFrame::STORAGE_OWNED_MEMORY,
      media::VideoPixelFormat::PIXEL_FORMAT_NV12, base::TimeDelta());
  rtc::scoped_refptr<webrtc::VideoFrameBuffer> owned_memory_frame_buffer =
      ConvertToWebRtcVideoFrameBuffer(std::move(owned_memory_frame), resources);
  EXPECT_EQ(owned_memory_frame_buffer->width(), kNaturalSize.width());
  EXPECT_EQ(owned_memory_frame_buffer->height(), kNaturalSize.height());

  // The NV12 frame should have the same size as the visible rect size
  auto* nv12_frame = owned_memory_frame_buffer->GetNV12();
  ASSERT_TRUE(nv12_frame);
  EXPECT_EQ(webrtc::VideoFrameBuffer::Type::kNV12, nv12_frame->type());
  EXPECT_EQ(nv12_frame->width(), kVisibleRect.size().width());
  EXPECT_EQ(nv12_frame->height(), kVisibleRect.size().height());
}

TEST(ConvertToWebRtcVideoFrameBufferTest, Nv12ScaleOwnedMemoryFrame) {
  const gfx::Size kCodedSize(1280, 960);
  const gfx::Rect kVisibleRect(0, 120, 1280, 720);
  const gfx::Size kNaturalSize(640, 360);
  auto resources =
      base::MakeRefCounted<WebRtcVideoFrameAdapter::SharedResources>(nullptr);

  // The adapter should report width and height from the natural size for
  // VideoFrame backed by owned memory.
  auto owned_memory_frame = CreateTestFrame(
      kCodedSize, kVisibleRect, kNaturalSize,
      media::VideoFrame::STORAGE_OWNED_MEMORY,
      media::VideoPixelFormat::PIXEL_FORMAT_NV12, base::TimeDelta());
  rtc::scoped_refptr<webrtc::VideoFrameBuffer> owned_memory_frame_buffer =
      ConvertToWebRtcVideoFrameBuffer(std::move(owned_memory_frame), resources);
  EXPECT_EQ(owned_memory_frame_buffer->width(), kNaturalSize.width());
  EXPECT_EQ(owned_memory_frame_buffer->height(), kNaturalSize.height());

  // The NV12 frame should have the same size as the natural size.
  auto* nv12_frame = owned_memory_frame_buffer->GetNV12();
  ASSERT_TRUE(nv12_frame);
  EXPECT_EQ(webrtc::VideoFrameBuffer::Type::kNV12, nv12_frame->type());
  EXPECT_EQ(nv12_frame->width(), kNaturalSize.width());
  EXPECT_EQ(nv12_frame->height(), kNaturalSize.height());
}

TEST(ConvertToWebRtcVideoFrameBufferTest,
     TextureFrameIsBlackWithNoSharedResources) {
  const gfx::Size kCodedSize(1280, 960);
  const gfx::Rect kVisibleRect(0, 120, 1280, 720);
  const gfx::Size kNaturalSize(640, 360);

  // The adapter should report width and height from the natural size for
  // VideoFrame backed by owned memory.
  auto owned_memory_frame = CreateTestFrame(
      kCodedSize, kVisibleRect, kNaturalSize, media::VideoFrame::STORAGE_OPAQUE,
      media::VideoPixelFormat::PIXEL_FORMAT_NV12, base::TimeDelta());
  rtc::scoped_refptr<webrtc::VideoFrameBuffer> frame_buffer =
      ConvertToWebRtcVideoFrameBuffer(std::move(owned_memory_frame), nullptr);
  EXPECT_EQ(frame_buffer->width(), kNaturalSize.width());
  EXPECT_EQ(frame_buffer->height(), kNaturalSize.height());

  // The NV12 frame should have the same size as the natural size, but be black
  // since we can't handle the texture with no shared resources.
  auto i420_frame = frame_buffer->ToI420();
  ASSERT_TRUE(i420_frame);
  EXPECT_EQ(i420_frame->width(), kNaturalSize.width());
  EXPECT_EQ(i420_frame->height(), kNaturalSize.height());
  EXPECT_EQ(0x0, i420_frame->DataY()[0]);
  EXPECT_EQ(0x80, i420_frame->DataU()[0]);
  EXPECT_EQ(0x80, i420_frame->DataV()[0]);
}

TEST(ConvertToWebRtcVideoFrameBufferTest,
     ConvertsTextureFrameWithSharedResources) {
  const gfx::Size kCodedSize(1280, 960);
  const gfx::Rect kVisibleRect(0, 120, 1280, 720);
  const gfx::Size kNaturalSize(640, 360);

  scoped_refptr<MockSharedResources> resources =
      base::MakeRefCounted<MockSharedResources>();

  // The adapter should report width and height from the natural size for
  // VideoFrame backed by owned memory.
  auto owned_memory_frame = CreateTestFrame(
      kCodedSize, kVisibleRect, kNaturalSize, media::VideoFrame::STORAGE_OPAQUE,
      media::VideoPixelFormat::PIXEL_FORMAT_NV12, base::TimeDelta());

  scoped_refptr<media::VideoFrame> memory_frame = CreateTestFrame(
      kCodedSize, kVisibleRect, kNaturalSize,
      media::VideoFrame::STORAGE_OWNED_MEMORY,
      media::VideoPixelFormat::PIXEL_FORMAT_ARGB, base::TimeDelta());
  // fill mock image with whilte color.
  memset(memory_frame->writable_data(media::VideoFrame::Plane::kARGB), 0xFF,
         kCodedSize.GetArea() * 4);

  // Should call texture conversion.
  resources->ExpectCreateFrameWithRealImplementation();
  resources->ExpectConvertAndScaleWithRealImplementation();
  EXPECT_CALL(*resources, ConstructVideoFrameFromTexture(_))
      .WillOnce(Return(memory_frame));

  rtc::scoped_refptr<webrtc::VideoFrameBuffer> frame_buffer =
      ConvertToWebRtcVideoFrameBuffer(std::move(owned_memory_frame), resources);
  EXPECT_EQ(frame_buffer->width(), kNaturalSize.width());
  EXPECT_EQ(frame_buffer->height(), kNaturalSize.height());

  // The NV12 frame should have the same size as the natural size, but be black
  // since we can't handle the texture with no shared resources.
  auto i420_frame = frame_buffer->ToI420();
  ASSERT_TRUE(i420_frame);
  EXPECT_EQ(i420_frame->width(), kNaturalSize.width());
  EXPECT_EQ(i420_frame->height(), kNaturalSize.height());
  // Returned memory frame should not be replaced by a black frame.
  EXPECT_NE(0x0, i420_frame->DataY()[0]);
}
}  // namespace blink

"""

```