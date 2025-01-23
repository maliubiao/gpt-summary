Response:
My thinking process to analyze the C++ code and answer the user's request goes like this:

1. **Understand the Goal:** The user wants to understand the functionality of `image_decoder_test.cc` in the Chromium Blink engine. They're specifically interested in its relation to JavaScript, HTML, CSS, any logical inferences made, and potential user/programmer errors.

2. **Identify the Core Purpose:** The file name `image_decoder_test.cc` immediately suggests its primary purpose: **testing the `ImageDecoder` class**. This is further confirmed by the inclusion of `<gtest/gtest.h>`, a common C++ testing framework.

3. **Break Down the Code:** I'll go through the code section by section, noting key elements and their purpose:

    * **Includes:**  These tell me what other parts of the Blink engine are being used. Crucially, it includes `image_decoder.h`, which confirms the testing focus. The presence of `media_buildflags.h` might indicate some media-related testing, but it's not central to the basic decoder logic being tested here. `wtf/forward.h` and `wtf/vector.h` indicate the use of Web Template Framework data structures.

    * **`TestImageDecoder` Class:** This is a custom class *derived from* `ImageDecoder`. This is a common pattern in testing: creating a simplified or specialized version of the class under test to isolate specific behaviors. The methods it overrides (`FilenameExtension`, `MimeType`, `DecodeSize`, `Decode`) and the custom methods it adds (`FrameBufferCache`, `ResetRequiredPreviousFrames`, `InitFrames`, `SetImageToHighBitDepthForTest`) give clues about what aspects of `ImageDecoder` are being tested. The constructors reveal different options for the decoder, such as high bit depth decoding.

    * **`TEST` Macros:**  These are the core of the Google Test framework. Each `TEST` defines an individual test case. I'll examine each test case to understand what specific functionality it's verifying.

4. **Analyze Individual Test Cases:**

    * **`sizeCalculationMayOverflow`:** This test checks how the `ImageDecoder` handles setting image dimensions and whether it prevents integer overflows when calculating memory requirements. It tests combinations of regular and high bit depth images and decoders.

    * **`requiredPreviousFrameIndex` (and variations):** These tests focus on how the decoder determines which previous frame is needed to render the current frame. This is crucial for animated images where frames might depend on the state of earlier frames. It explores different disposal methods (`kDisposeKeep`, `kDisposeOverwritePrevious`, `kDisposeOverwriteBgcolor`) and blending modes (`kBlendAtopBgcolor`).

    * **`clearCacheExceptFrame` (and variations):** These tests check the functionality of clearing the frame buffer cache, either entirely or while preserving a specific frame. This is relevant for memory management and optimizing resource usage.

    * **`decodedSizeLimitBoundary` and `decodedSizeUnlimited` (and platform-specific variation):** These tests verify the behavior of the decoder when a maximum decoded size limit is imposed. It appears this behavior is different on Fuchsia compared to other platforms.

    * **`hasSufficientDataToSniffMimeTypeAvif`:** This test is specific to AVIF image decoding. It checks if the decoder can correctly identify the MIME type of an AVIF image based on a portion of its data.

5. **Relate to JavaScript, HTML, and CSS:** This requires connecting the low-level C++ functionality to the web development context.

    * **JavaScript:** JavaScript image APIs (like `Image()`, `createImageBitmap()`, canvas drawing) ultimately rely on the browser's image decoding capabilities. The `ImageDecoder` is a core part of that. If the `ImageDecoder` has bugs, it could manifest as incorrect image rendering or crashes in JavaScript-driven image manipulations.

    * **HTML:** The `<img>` tag is the primary way to embed images in HTML. The browser uses an appropriate `ImageDecoder` based on the image's format (determined by MIME type sniffing). The tests here ensure that images loaded through `<img>` are decoded correctly and efficiently.

    * **CSS:** CSS properties like `background-image` also trigger image loading and decoding. The `ImageDecoder` is involved in rendering these background images. The tests, especially those related to disposal methods and blending, directly relate to how animated GIFs or other multi-frame images behave when used as CSS backgrounds.

6. **Logical Inferences and Examples:**

    * **Overflow Prevention:** The `sizeCalculationMayOverflow` test demonstrates a logical check to prevent memory allocation issues. *Input: Large width and height values. Output: `SetSize` returns `false`.*

    * **Frame Dependency:** The `requiredPreviousFrameIndex` tests illustrate the logic of determining frame dependencies based on disposal methods. *Input: Frame with `kDisposeOverwritePrevious`. Output: `RequiredPreviousFrameIndex` skips over the overwritten frame.*

7. **Common User/Programmer Errors:**

    * **Memory Issues:**  The size calculation tests relate to potential memory exhaustion errors if the decoder doesn't handle large images correctly. A programmer might incorrectly assume they can decode arbitrarily large images without checks.

    * **Animation Bugs:** Incorrect handling of disposal methods can lead to visual glitches in animated images. A common user error might be expecting an animation to work correctly without understanding how disposal methods affect frame rendering. A programmer error could be implementing the disposal method logic incorrectly in the decoder.

    * **Format Support:** The AVIF sniffing test highlights the importance of correctly identifying image formats. A user might encounter a "broken image" if the browser fails to recognize the image format. A programmer error could be an incomplete or incorrect implementation of MIME type sniffing.

8. **Structure and Refine the Answer:** Finally, I organize the information into a clear and structured answer, addressing each point raised in the user's request. I use headings and bullet points to improve readability. I also make sure to provide concrete examples to illustrate the concepts.
这个文件 `image_decoder_test.cc` 是 Chromium Blink 引擎中用于测试 `ImageDecoder` 及其相关功能的 C++ 源代码文件。  它的主要目的是确保图像解码器能够正确、高效地工作，并且能够处理各种边缘情况和潜在的错误。

以下是它功能的详细列举：

**主要功能:**

1. **单元测试 `ImageDecoder` 类:**  该文件包含了多个单元测试用例，使用 Google Test 框架 (`testing/gtest/include/gtest/gtest.h`) 来验证 `ImageDecoder` 类的各个方面。

2. **测试图像尺寸计算:**  测试 `ImageDecoder::SetSize()` 方法，验证其在处理不同尺寸的图像时是否能正确工作，特别是要防止整数溢出导致的安全问题。

3. **测试帧依赖关系 (针对动画图像):** 针对动画图像 (如 GIF)，测试 `ImageDecoder` 如何确定当前帧是否需要依赖之前的帧才能正确渲染。这涉及到 `ImageFrame` 的处理，包括其 disposal method (处置方法) 和 blending mode (混合模式)。

4. **测试缓存管理:**  测试 `ImageDecoder` 的缓存机制，特别是 `ClearCacheExceptFrame()` 方法，确保在不需要保留所有帧的情况下能够正确清除缓存，以节省内存。

5. **测试解码尺寸限制 (特定平台):** 在某些平台上 (如 Fuchsia)，测试 `ImageDecoder` 是否能够正确处理最大解码尺寸的限制。

6. **测试 MIME 类型嗅探 (特定格式):**  针对特定的图像格式 (如 AVIF)，测试 `ImageDecoder` 是否有足够的数据来正确嗅探 (识别) 图像的 MIME 类型。

**与 JavaScript, HTML, CSS 的关系:**

`ImageDecoder` 是浏览器渲染图像的核心组件之一。当浏览器在解析 HTML、CSS 或执行 JavaScript 时遇到图像资源时，就需要使用 `ImageDecoder` 来解码这些图像，以便进行后续的渲染和显示。

* **HTML:** 当 HTML 中包含 `<img>` 标签，或者通过 CSS 的 `background-image` 等属性引用图像时，浏览器会下载图像数据并使用相应的 `ImageDecoder` 来解码。 `image_decoder_test.cc` 中测试的解码功能直接影响到 HTML 页面中图像的显示是否正确。

    * **举例:** 如果 `image_decoder_test.cc` 中关于尺寸计算的测试失败，可能导致在 HTML 中加载非常大的图像时出现渲染错误或崩溃。如果关于帧依赖的测试失败，可能会导致动画 GIF 在 HTML 页面中播放时出现闪烁或帧丢失。

* **CSS:**  CSS 中使用的图像 (例如背景图像、列表标记等) 同样需要 `ImageDecoder` 进行处理。

    * **举例:** 如果 `image_decoder_test.cc` 中关于 `kDisposeOverwriteBgcolor` 处置方法的测试存在问题，可能会导致使用该处置方法的动画 GIF 作为 CSS 背景时，背景色的覆盖不正确。

* **JavaScript:** JavaScript 可以通过 `Image()` 对象或者 Canvas API 来加载和操作图像。这些操作最终都会调用底层的图像解码功能。

    * **举例:**  如果 JavaScript 代码使用 `createImageBitmap()` 创建一个图像位图，而 `image_decoder_test.cc` 中关于高位深解码的测试有问题，可能会导致 JavaScript 获取到的图像数据不正确。

**逻辑推理的举例说明:**

* **假设输入:**  一个 GIF 图像，其中第二帧的处置方法设置为 `ImageFrame::kDisposeOverwritePrevious`，且第三帧的原始帧矩形与第二帧重叠。
* **逻辑推理:**  根据 `ImageDecoder` 的逻辑，当解码到第三帧时，它会检查第二帧的处置方法。由于是 `kDisposeOverwritePrevious`，且覆盖了当前帧的区域，所以解码器会认为第三帧不需要依赖第二帧之前的内容，可以从空白状态开始绘制。
* **输出 (测试结果):**  `requiredPreviousFrameIndex` 测试应该断言第三帧的 `RequiredPreviousFrameIndex()` 返回 `kNotFound` 或者一个早于第二帧的索引。

* **假设输入:** 一个图像，其宽度和高度的乘积，再乘以每个像素的字节数，超过了系统允许的最大整数值。
* **逻辑推理:**  `ImageDecoder` 的 `SetSize()` 方法应该能够检测到这种潜在的溢出，并返回 `false`，表示设置尺寸失败。
* **输出 (测试结果):** `sizeCalculationMayOverflow` 测试会断言 `SetSize()` 方法在遇到这样的输入时返回 `false`。

**用户或编程常见的使用错误举例:**

* **内存不足错误:**  用户可能会尝试加载非常大的图像，导致浏览器内存不足。`image_decoder_test.cc` 中的尺寸计算测试旨在防止由于整数溢出导致的更严重的错误，但无法完全阻止内存不足的情况。  **用户错误:** 加载过大的图片，没有考虑设备内存限制。

* **动画渲染错误:**  开发者可能不理解 GIF 等动画图像的帧处置方法，导致动画显示不符合预期。例如，错误地使用了 `kDisposeOverwritePrevious`，导致某些帧的内容被错误地清除。 **编程错误:**  在生成动画图像时，错误地设置了帧的处置方法。

* **解码失败:**  用户可能会尝试加载损坏的或者浏览器不支持的图像格式。虽然 `image_decoder_test.cc` 主要测试已支持格式的解码器，但如果解码器本身存在错误，也可能导致本应正常解码的图像解码失败。 **用户错误:**  尝试加载损坏的图片文件。 **编程错误:**  图像编码器生成了不符合规范的图像文件。

* **跨域问题:** 虽然与 `ImageDecoder` 的直接功能关系不大，但当通过 JavaScript 加载跨域图像时，如果服务器没有设置正确的 CORS 头，会导致解码后的图像数据无法被 JavaScript 访问。这与图像的解码过程有关，但更多的是网络安全策略问题。 **编程错误:**  服务器没有配置正确的 CORS 头。

总而言之，`image_decoder_test.cc` 是 Blink 引擎中一个至关重要的测试文件，它确保了图像解码功能的稳定性和正确性，从而保证了网页上图像的正常显示和用户体验。其测试覆盖了图像解码的多个关键方面，包括尺寸处理、动画帧管理、缓存控制以及平台特定的限制。

### 提示词
```
这是目录为blink/renderer/platform/image-decoders/image_decoder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/image-decoders/image_decoder.h"

#include <memory>
#include "build/build_config.h"
#include "media/media_buildflags.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/image-decoders/image_frame.h"
#include "third_party/blink/renderer/platform/wtf/forward.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

class TestImageDecoder : public ImageDecoder {
 public:
  explicit TestImageDecoder(
      ImageDecoder::HighBitDepthDecodingOption high_bit_depth_decoding_option,
      wtf_size_t max_decoded_bytes = kNoDecodedImageByteLimit)
      : ImageDecoder(kAlphaNotPremultiplied,
                     high_bit_depth_decoding_option,
                     ColorBehavior::kTransformToSRGB,
                     cc::AuxImage::kDefault,
                     max_decoded_bytes) {}

  TestImageDecoder() : TestImageDecoder(ImageDecoder::kDefaultBitDepth) {}

  String FilenameExtension() const override { return ""; }
  const AtomicString& MimeType() const override { return g_empty_atom; }

  Vector<ImageFrame, 1>& FrameBufferCache() { return frame_buffer_cache_; }

  void ResetRequiredPreviousFrames(bool known_opaque = false) {
    for (size_t i = 0; i < frame_buffer_cache_.size(); ++i) {
      frame_buffer_cache_[i].SetRequiredPreviousFrameIndex(
          FindRequiredPreviousFrame(i, known_opaque));
    }
  }

  void InitFrames(wtf_size_t num_frames,
                  unsigned width = 100,
                  unsigned height = 100) {
    SetSize(width, height);
    frame_buffer_cache_.resize(num_frames);
    for (wtf_size_t i = 0; i < num_frames; ++i) {
      frame_buffer_cache_[i].SetOriginalFrameRect(gfx::Rect(width, height));
    }
  }

  bool ImageIsHighBitDepth() override { return image_is_high_bit_depth_; }
  void SetImageToHighBitDepthForTest() { image_is_high_bit_depth_ = true; }

 private:
  bool image_is_high_bit_depth_ = false;
  void DecodeSize() override {}
  void Decode(wtf_size_t index) override {}
};

TEST(ImageDecoderTest, sizeCalculationMayOverflow) {
  // Test coverage:
  // Regular bit depth image with regular decoder
  // Regular bit depth image with high bit depth decoder
  // High bit depth image with regular decoder
  // High bit depth image with high bit depth decoder
  bool high_bit_depth_decoder_status[] = {false, true};
  bool high_bit_depth_image_status[] = {false, true};

  for (bool high_bit_depth_decoder : high_bit_depth_decoder_status) {
    for (bool high_bit_depth_image : high_bit_depth_image_status) {
      std::unique_ptr<TestImageDecoder> decoder;
      if (high_bit_depth_decoder) {
        decoder = std::make_unique<TestImageDecoder>(
            ImageDecoder::kHighBitDepthToHalfFloat);
      } else {
        decoder = std::make_unique<TestImageDecoder>();
      }
      if (high_bit_depth_image) {
        decoder->SetImageToHighBitDepthForTest();
      }

      unsigned log_pixel_size = 2;  // pixel is 4 bytes
      if (high_bit_depth_decoder && high_bit_depth_image) {
        log_pixel_size = 3;  // pixel is 8 byts
      }
      unsigned overflow_dim_shift = 31 - log_pixel_size;
      unsigned overflow_dim_shift_half = (overflow_dim_shift + 1) / 2;

      EXPECT_FALSE(decoder->SetSize(1 << overflow_dim_shift, 1));
      EXPECT_FALSE(decoder->SetSize(1, 1 << overflow_dim_shift));
      EXPECT_FALSE(decoder->SetSize(1 << overflow_dim_shift_half,
                                    1 << overflow_dim_shift_half));
      EXPECT_TRUE(decoder->SetSize(1 << (overflow_dim_shift - 1), 1));
      EXPECT_TRUE(decoder->SetSize(1, 1 << (overflow_dim_shift - 1)));
      EXPECT_TRUE(decoder->SetSize(1 << (overflow_dim_shift_half - 1),
                                   1 << (overflow_dim_shift_half - 1)));
    }
  }
}

TEST(ImageDecoderTest, requiredPreviousFrameIndex) {
  std::unique_ptr<TestImageDecoder> decoder(
      std::make_unique<TestImageDecoder>());
  decoder->InitFrames(6);
  Vector<ImageFrame, 1>& frame_buffers = decoder->FrameBufferCache();

  frame_buffers[1].SetDisposalMethod(ImageFrame::kDisposeKeep);
  frame_buffers[2].SetDisposalMethod(ImageFrame::kDisposeOverwritePrevious);
  frame_buffers[3].SetDisposalMethod(ImageFrame::kDisposeOverwritePrevious);
  frame_buffers[4].SetDisposalMethod(ImageFrame::kDisposeKeep);

  decoder->ResetRequiredPreviousFrames();

  // The first frame doesn't require any previous frame.
  EXPECT_EQ(kNotFound, frame_buffers[0].RequiredPreviousFrameIndex());
  // The previous DisposeNotSpecified frame is required.
  EXPECT_EQ(0u, frame_buffers[1].RequiredPreviousFrameIndex());
  // DisposeKeep is treated as DisposeNotSpecified.
  EXPECT_EQ(1u, frame_buffers[2].RequiredPreviousFrameIndex());
  // Previous DisposeOverwritePrevious frames are skipped.
  EXPECT_EQ(1u, frame_buffers[3].RequiredPreviousFrameIndex());
  EXPECT_EQ(1u, frame_buffers[4].RequiredPreviousFrameIndex());
  EXPECT_EQ(4u, frame_buffers[5].RequiredPreviousFrameIndex());
}

TEST(ImageDecoderTest, requiredPreviousFrameIndexDisposeOverwriteBgcolor) {
  std::unique_ptr<TestImageDecoder> decoder(
      std::make_unique<TestImageDecoder>());
  decoder->InitFrames(3);
  Vector<ImageFrame, 1>& frame_buffers = decoder->FrameBufferCache();

  // Fully covering DisposeOverwriteBgcolor previous frame resets the starting
  // state.
  frame_buffers[1].SetDisposalMethod(ImageFrame::kDisposeOverwriteBgcolor);
  decoder->ResetRequiredPreviousFrames();
  EXPECT_EQ(kNotFound, frame_buffers[2].RequiredPreviousFrameIndex());

  // Partially covering DisposeOverwriteBgcolor previous frame is required by
  // this frame.
  frame_buffers[1].SetOriginalFrameRect(gfx::Rect(50, 50, 50, 50));
  decoder->ResetRequiredPreviousFrames();
  EXPECT_EQ(1u, frame_buffers[2].RequiredPreviousFrameIndex());
}

TEST(ImageDecoderTest, requiredPreviousFrameIndexForFrame1) {
  std::unique_ptr<TestImageDecoder> decoder(
      std::make_unique<TestImageDecoder>());
  decoder->InitFrames(2);
  Vector<ImageFrame, 1>& frame_buffers = decoder->FrameBufferCache();

  decoder->ResetRequiredPreviousFrames();
  EXPECT_EQ(0u, frame_buffers[1].RequiredPreviousFrameIndex());

  // The first frame with DisposeOverwritePrevious or DisposeOverwriteBgcolor
  // resets the starting state.
  frame_buffers[0].SetDisposalMethod(ImageFrame::kDisposeOverwritePrevious);
  decoder->ResetRequiredPreviousFrames();
  EXPECT_EQ(kNotFound, frame_buffers[1].RequiredPreviousFrameIndex());
  frame_buffers[0].SetDisposalMethod(ImageFrame::kDisposeOverwriteBgcolor);
  decoder->ResetRequiredPreviousFrames();
  EXPECT_EQ(kNotFound, frame_buffers[1].RequiredPreviousFrameIndex());

  // ... even if it partially covers.
  frame_buffers[0].SetOriginalFrameRect(gfx::Rect(50, 50, 50, 50));

  frame_buffers[0].SetDisposalMethod(ImageFrame::kDisposeOverwritePrevious);
  decoder->ResetRequiredPreviousFrames();
  EXPECT_EQ(kNotFound, frame_buffers[1].RequiredPreviousFrameIndex());
  frame_buffers[0].SetDisposalMethod(ImageFrame::kDisposeOverwriteBgcolor);
  decoder->ResetRequiredPreviousFrames();
  EXPECT_EQ(kNotFound, frame_buffers[1].RequiredPreviousFrameIndex());
}

TEST(ImageDecoderTest, requiredPreviousFrameIndexBlendAtopBgcolor) {
  std::unique_ptr<TestImageDecoder> decoder(
      std::make_unique<TestImageDecoder>());
  decoder->InitFrames(3);
  Vector<ImageFrame, 1>& frame_buffers = decoder->FrameBufferCache();

  frame_buffers[1].SetOriginalFrameRect(gfx::Rect(25, 25, 50, 50));
  frame_buffers[2].SetAlphaBlendSource(ImageFrame::kBlendAtopBgcolor);

  // A full frame with 'blending method == BlendAtopBgcolor' doesn't depend on
  // any prior frames.
  for (int dispose_method = ImageFrame::kDisposeNotSpecified;
       dispose_method <= ImageFrame::kDisposeOverwritePrevious;
       ++dispose_method) {
    frame_buffers[1].SetDisposalMethod(
        static_cast<ImageFrame::DisposalMethod>(dispose_method));
    decoder->ResetRequiredPreviousFrames();
    EXPECT_EQ(kNotFound, frame_buffers[2].RequiredPreviousFrameIndex());
  }

  // A non-full frame with 'blending method == BlendAtopBgcolor' does depend on
  // a prior frame.
  frame_buffers[2].SetOriginalFrameRect(gfx::Rect(50, 50, 50, 50));
  for (int dispose_method = ImageFrame::kDisposeNotSpecified;
       dispose_method <= ImageFrame::kDisposeOverwritePrevious;
       ++dispose_method) {
    frame_buffers[1].SetDisposalMethod(
        static_cast<ImageFrame::DisposalMethod>(dispose_method));
    decoder->ResetRequiredPreviousFrames();
    EXPECT_NE(kNotFound, frame_buffers[2].RequiredPreviousFrameIndex());
  }
}

TEST(ImageDecoderTest, requiredPreviousFrameIndexKnownOpaque) {
  std::unique_ptr<TestImageDecoder> decoder(
      std::make_unique<TestImageDecoder>());
  decoder->InitFrames(3);
  Vector<ImageFrame, 1>& frame_buffers = decoder->FrameBufferCache();

  frame_buffers[1].SetOriginalFrameRect(gfx::Rect(25, 25, 50, 50));

  // A full frame that is known to be opaque doesn't depend on any prior frames.
  for (int dispose_method = ImageFrame::kDisposeNotSpecified;
       dispose_method <= ImageFrame::kDisposeOverwritePrevious;
       ++dispose_method) {
    frame_buffers[1].SetDisposalMethod(
        static_cast<ImageFrame::DisposalMethod>(dispose_method));
    decoder->ResetRequiredPreviousFrames(true);
    EXPECT_EQ(kNotFound, frame_buffers[2].RequiredPreviousFrameIndex());
  }

  // A non-full frame that is known to be opaque does depend on a prior frame.
  frame_buffers[2].SetOriginalFrameRect(gfx::Rect(50, 50, 50, 50));
  for (int dispose_method = ImageFrame::kDisposeNotSpecified;
       dispose_method <= ImageFrame::kDisposeOverwritePrevious;
       ++dispose_method) {
    frame_buffers[1].SetDisposalMethod(
        static_cast<ImageFrame::DisposalMethod>(dispose_method));
    decoder->ResetRequiredPreviousFrames(true);
    EXPECT_NE(kNotFound, frame_buffers[2].RequiredPreviousFrameIndex());
  }
}

TEST(ImageDecoderTest, clearCacheExceptFrameDoNothing) {
  std::unique_ptr<TestImageDecoder> decoder(
      std::make_unique<TestImageDecoder>());
  decoder->ClearCacheExceptFrame(0);

  // This should not crash.
  decoder->InitFrames(20);
  decoder->ClearCacheExceptFrame(kNotFound);
}

TEST(ImageDecoderTest, clearCacheExceptFrameAll) {
  const size_t kNumFrames = 10;
  std::unique_ptr<TestImageDecoder> decoder(
      std::make_unique<TestImageDecoder>());
  decoder->InitFrames(kNumFrames);
  Vector<ImageFrame, 1>& frame_buffers = decoder->FrameBufferCache();
  for (size_t i = 0; i < kNumFrames; ++i) {
    frame_buffers[i].SetStatus(i % 2 ? ImageFrame::kFramePartial
                                     : ImageFrame::kFrameComplete);
  }

  decoder->ClearCacheExceptFrame(kNotFound);

  for (size_t i = 0; i < kNumFrames; ++i) {
    SCOPED_TRACE(testing::Message() << i);
    EXPECT_EQ(ImageFrame::kFrameEmpty, frame_buffers[i].GetStatus());
  }
}

TEST(ImageDecoderTest, clearCacheExceptFramePreverveClearExceptFrame) {
  const wtf_size_t kNumFrames = 10;
  std::unique_ptr<TestImageDecoder> decoder(
      std::make_unique<TestImageDecoder>());
  decoder->InitFrames(kNumFrames);
  Vector<ImageFrame, 1>& frame_buffers = decoder->FrameBufferCache();
  for (size_t i = 0; i < kNumFrames; ++i) {
    frame_buffers[i].SetStatus(ImageFrame::kFrameComplete);
  }

  decoder->ResetRequiredPreviousFrames();
  decoder->ClearCacheExceptFrame(5);
  for (wtf_size_t i = 0; i < kNumFrames; ++i) {
    SCOPED_TRACE(testing::Message() << i);
    if (i == 5) {
      EXPECT_EQ(ImageFrame::kFrameComplete, frame_buffers[i].GetStatus());
    } else {
      EXPECT_EQ(ImageFrame::kFrameEmpty, frame_buffers[i].GetStatus());
    }
  }
}

#if BUILDFLAG(IS_FUCHSIA)

TEST(ImageDecoderTest, decodedSizeLimitBoundary) {
  constexpr unsigned kWidth = 100;
  constexpr unsigned kHeight = 200;
  constexpr unsigned kBitDepth = 4;
  std::unique_ptr<TestImageDecoder> decoder(std::make_unique<TestImageDecoder>(
      ImageDecoder::kDefaultBitDepth, (kWidth * kHeight * kBitDepth)));

  // Smallest allowable size, should succeed.
  EXPECT_TRUE(decoder->SetSize(1, 1));
  EXPECT_TRUE(decoder->IsSizeAvailable());
  EXPECT_FALSE(decoder->Failed());

  // At the limit, should succeed.
  EXPECT_TRUE(decoder->SetSize(kWidth, kHeight));
  EXPECT_TRUE(decoder->IsSizeAvailable());
  EXPECT_FALSE(decoder->Failed());

  // Just over the limit, should fail.
  EXPECT_TRUE(decoder->SetSize(kWidth + 1, kHeight));
  EXPECT_FALSE(decoder->IsSizeAvailable());
  EXPECT_TRUE(decoder->Failed());
}

TEST(ImageDecoderTest, decodedSizeUnlimited) {
  // Very large values for width and height should be OK.
  constexpr unsigned kWidth = 10000;
  constexpr unsigned kHeight = 10000;

  std::unique_ptr<TestImageDecoder> decoder(std::make_unique<TestImageDecoder>(
      ImageDecoder::kDefaultBitDepth, ImageDecoder::kNoDecodedImageByteLimit));
  EXPECT_TRUE(decoder->SetSize(kWidth, kHeight));
  EXPECT_TRUE(decoder->IsSizeAvailable());
  EXPECT_FALSE(decoder->Failed());
}

#else

// The limit is currently ignored on non-Fuchsia platforms (except for
// JPEG, which would decode a down-sampled version).
TEST(ImageDecoderTest, decodedSizeLimitIsIgnored) {
  constexpr unsigned kWidth = 100;
  constexpr unsigned kHeight = 200;
  constexpr unsigned kBitDepth = 4;
  std::unique_ptr<TestImageDecoder> decoder(std::make_unique<TestImageDecoder>(
      ImageDecoder::kDefaultBitDepth, (kWidth * kHeight * kBitDepth)));

  // Just over the limit. The limit should be ignored.
  EXPECT_TRUE(decoder->SetSize(kWidth + 1, kHeight));
  EXPECT_TRUE(decoder->IsSizeAvailable());
  EXPECT_FALSE(decoder->Failed());
}

#endif  // BUILDFLAG(IS_FUCHSIA)

#if BUILDFLAG(ENABLE_AV1_DECODER)
TEST(ImageDecoderTest, hasSufficientDataToSniffMimeTypeAvif) {
  // The first 36 bytes of the Netflix AVIF test image
  // Chimera-AV1-10bit-1280x720-2380kbps-100.avif. Since the major_brand is
  // not "avif" or "avis", we must parse the compatible_brands to determine if
  // this is an AVIF image.
  constexpr uint8_t kData[] = {
      // A File Type Box.
      0x00, 0x00, 0x00, 0x1c,  // unsigned int(32) size; 0x1c = 28
      'f', 't', 'y', 'p',      // unsigned int(32) type = boxtype;
      'm', 'i', 'f', '1',      // unsigned int(32) major_brand;
      0x00, 0x00, 0x00, 0x00,  // unsigned int(32) minor_version;
      'm', 'i', 'f', '1',      // unsigned int(32) compatible_brands[];
      'a', 'v', 'i', 'f',      //
      'm', 'i', 'a', 'f',      //
      // The beginning of a Media Data Box.
      0x00, 0x00, 0xa4, 0x3a,  // unsigned int(32) size;
      'm', 'd', 'a', 't'       // unsigned int(32) type = boxtype;
  };

  scoped_refptr<SharedBuffer> buffer = SharedBuffer::Create<size_t>(kData, 8);
  EXPECT_FALSE(ImageDecoder::HasSufficientDataToSniffMimeType(*buffer));
  EXPECT_EQ(ImageDecoder::SniffMimeType(buffer), String());
  buffer->Append<size_t>(kData + 8, 8);
  EXPECT_FALSE(ImageDecoder::HasSufficientDataToSniffMimeType(*buffer));
  EXPECT_EQ(ImageDecoder::SniffMimeType(buffer), String());
  buffer->Append<size_t>(kData + 16, sizeof(kData) - 16);
  EXPECT_TRUE(ImageDecoder::HasSufficientDataToSniffMimeType(*buffer));
  EXPECT_EQ(ImageDecoder::SniffMimeType(buffer), "image/avif");
}
#endif  // BUILDFLAG(ENABLE_AV1_DECODER)

}  // namespace blink
```