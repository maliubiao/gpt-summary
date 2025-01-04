Response:
Let's break down the thought process for analyzing the provided C++ test file.

1. **Understand the Goal:** The primary goal is to understand the functionality of the test file (`webp_image_decoder_test.cc`) within the Chromium Blink engine and identify its relationships with web technologies (JavaScript, HTML, CSS). Additionally, we need to extract information about assumptions, inputs, outputs, and common usage errors.

2. **Identify the Core Subject:** The file name itself (`webp_image_decoder_test.cc`) strongly suggests that this file contains tests for the `WEBPImageDecoder` class. This class is likely responsible for decoding WebP image format data.

3. **Scan for Key Imports and Namespaces:**  The `#include` directives provide initial clues:
    * `webp_image_decoder.h`: Confirms that this is the class being tested.
    * `<memory>`: Indicates usage of smart pointers (like `std::unique_ptr`).
    * `base/metrics/...`: Suggests the tests involve measuring performance or other metrics.
    * `base/test/...`:  Indicates the use of Google Test framework for unit testing.
    * `testing/gtest/...`:  Further confirmation of Google Test usage.
    * `public/platform/web_data.h`: Points towards interaction with Blink's platform layer, likely dealing with raw data.
    * `image-decoders/image_decoder_test_helpers.h`: Implies the use of shared testing utilities for image decoding.
    * `wtf/shared_buffer.h`, `wtf/vector.h`:  Blink's internal utility classes for managing memory and data structures.

    The `namespace blink` signifies this code belongs to the Blink rendering engine.

4. **Analyze Test Structure:**  The code uses Google Test's `TEST` macro. Each `TEST` block represents a specific test case. The names of these test cases often provide valuable information about what's being tested (e.g., `uniqueGenerationIDs`, `verifyAnimationParametersTransparentImage`, `invalidImages`, `progressiveDecode`).

5. **Group Tests by Functionality:** Observe the naming patterns and the actions within the test cases to group them into logical categories:
    * **Animated WebP:** Tests specifically for animated WebP images (look for `AnimatedWebPTests`). These tests examine frame parameters, animation loops, blending modes, and handling of invalid/truncated data.
    * **Static WebP:** Tests for static (non-animated) WebP images (look for `StaticWebPTests`). These tests focus on decoding, size availability, and bit-per-pixel (BPP) histogram generation.
    * **General Decoding:** Some tests appear to be more general, like `progressiveDecode`, `randomFrameDecode`, and tests for handling data reallocation and cache clearing.
    * **Error Handling:** Tests named `invalidImages` and those involving truncated data specifically check error conditions.

6. **Examine Test Logic Within Categories:**  For each group, analyze the common patterns:
    * **Creating a Decoder:** Most tests start by creating an instance of `WEBPImageDecoder`.
    * **Loading Test Data:**  The `ReadFileToSharedBuffer` function is used to load WebP image data from files.
    * **Setting Data:** The `decoder->SetData()` method feeds the image data to the decoder.
    * **Assertions and Expectations:** `ASSERT_TRUE`, `EXPECT_EQ`, `EXPECT_FALSE`, `EXPECT_GT` are used to verify the decoder's behavior. Look for specific properties being checked (e.g., `FrameCount()`, `RepetitionCount()`, `DecodeFrameBufferAtIndex()`, frame parameters like offsets, dimensions, disposal methods, durations, alpha blending).
    * **Helper Functions:**  Notice the `TestByteByByteDecode`, `TestInvalidImage`, `TestProgressiveDecoding`, `TestRandomFrameDecode`, etc. These are helper functions that encapsulate common testing patterns, making the individual tests more concise. Infer their purpose from their names and usage.

7. **Identify Connections to Web Technologies:**
    * **Images in Web Pages:** The very nature of an image decoder connects directly to the `<image>` tag in HTML and the `background-image` property in CSS. WebP is a common image format used on the web.
    * **JavaScript and the Canvas API:**  JavaScript can interact with images through the Canvas API. Decoded image data can be drawn onto a canvas. The tests verify the correctness of the decoded data, which is crucial for accurate rendering in a canvas.
    * **Animation:** Animated WebP directly relates to how animations are displayed in web browsers. The tests ensure correct frame sequencing, timing, and blending.
    * **Performance:** The histogram tests indicate an interest in measuring the performance and efficiency of WebP decoding, which is vital for a smooth user experience.

8. **Infer Assumptions, Inputs, and Outputs:**
    * **Assumptions:** The tests assume the existence of specific WebP image files in the `/images/resources/` directory. They also assume that the underlying WebP decoding library is functioning correctly.
    * **Inputs:** The primary input is the raw byte stream of WebP image data (loaded from files). Other inputs might include flags passed to the decoder (e.g., alpha options).
    * **Outputs:** The outputs are the decoded image frames (represented by `ImageFrame` objects), their properties (dimensions, offsets, durations, etc.), and the overall status of the decoding process (success/failure, frame completeness).

9. **Identify Potential User/Programming Errors:**
    * **Invalid Image Data:**  The `invalidImages` tests directly address the scenario of users providing corrupted or malformed WebP files.
    * **Truncated Data:** Tests for truncated files highlight the importance of providing complete image data.
    * **Incorrect Usage of Decoding Methods:** The `reproCrash` test suggests a scenario where a specific sequence of calls could lead to issues, indicating potential misuse of the decoder's API.
    * **Resource Management:** While not explicitly tested in this file, incorrect memory management related to the decoded image data could be a source of errors.

10. **Synthesize and Organize:**  Finally, organize the collected information into a clear and structured answer, covering the requested aspects: functionality, relationship to web technologies, logical reasoning (assumptions, inputs, outputs), and common errors. Use clear examples to illustrate the connections to JavaScript, HTML, and CSS.

By following this systematic approach, even without deep prior knowledge of the Blink engine's internals, you can effectively analyze the C++ test file and extract the key information. The process involves understanding the purpose of the code, identifying its components, and inferring its behavior through the structure and logic of the tests.
这个C++文件 `webp_image_decoder_test.cc` 是 Chromium Blink 引擎中用于测试 `WEBPImageDecoder` 类的单元测试文件。它的主要功能是验证 WebP 图像解码器的正确性和鲁棒性。

以下是该文件的功能列表以及与 JavaScript、HTML、CSS 的关系、逻辑推理和常见错误：

**功能列表:**

1. **解码静态 WebP 图像:**  测试解码非动画的 WebP 图片，验证解码后的图像数据是否正确，包括尺寸、颜色等信息。
2. **解码动画 WebP 图像:**  测试解码动画 WebP 图片，验证对多帧图像的处理，包括：
    * **帧的提取和解码:**  验证能否正确提取每一帧的图像数据。
    * **帧的元数据:** 验证能否正确解析和获取每一帧的偏移量、尺寸、持续时间、处理方式（Disposal Method）、混合模式（Alpha Blend Source）等参数。
    * **动画循环次数:**  验证能否正确解析动画的循环次数。
3. **处理无效的 WebP 图像:** 测试解码器在遇到损坏或格式错误的 WebP 图片时的行为，例如：
    * **文件截断:**  测试文件在不同位置被截断的情况。
    * **帧数据错误:** 测试帧数据本身存在错误的情况。
    * **头部信息错误:** 测试 WebP 文件头部信息不正确的情况。
4. **渐进式解码:** 测试解码器是否支持渐进式解码，即可以逐步解码不完整的图像数据。
5. **随机帧解码:** 测试能否直接解码指定帧，而无需按顺序解码前面的帧。
6. **缓存管理:** 测试解码器的缓存机制，例如清空缓存、保留特定帧的缓存等。
7. **Alpha 混合:** 测试解码器处理带透明通道的 WebP 图像的能力，并验证 alpha 混合的正确性。
8. **尺寸可用性检测:** 测试在解码部分数据后，是否能正确判断图像的尺寸是否已经可用。
9. **位/像素 (BPP) 统计:**  测试解码器是否会收集解码 WebP 图像的 BPP 信息并记录到直方图中，用于性能分析。

**与 JavaScript, HTML, CSS 的关系:**

WebP 是一种图片格式，在网页中被广泛使用。这个测试文件直接关系到浏览器如何渲染 WebP 图片，这与 JavaScript、HTML 和 CSS 都有着密切的联系：

* **HTML (`<img>` 标签):**  当 HTML 中使用 `<img src="image.webp">` 引入 WebP 图片时，Blink 引擎会调用 `WEBPImageDecoder` 来解码该图片，以便在页面上显示。这个测试文件保证了解码器的正确性，从而确保图片能正确显示。
    * **举例:**  假设一个包含动画 WebP 图片的 HTML 页面：
      ```html
      <!DOCTYPE html>
      <html>
      <body>
          <img src="animated.webp">
      </body>
      </html>
      ```
      `webp_image_decoder_test.cc` 中的测试用例，例如 `AnimatedWebPTests` 中的 `verifyAnimationParametersTransparentImage`，确保了 Blink 能够正确解析 `animated.webp` 中的帧信息（如持续时间、偏移量等），从而实现动画的正确播放。

* **CSS (`background-image` 属性):**  CSS 也可以使用 WebP 图片作为背景：
    ```css
    .container {
        background-image: url("background.webp");
    }
    ```
    `webp_image_decoder_test.cc` 中的测试用例，例如 `StaticWebPTests` 中的测试，确保了背景图片能够被正确解码并渲染。

* **JavaScript (Canvas API, Fetch API 等):** JavaScript 可以通过多种方式操作图片：
    * **Canvas API:**  可以使用 Canvas API 将解码后的 WebP 图片绘制到 `<canvas>` 元素上。 `webp_image_decoder_test.cc` 确保了 `WEBPImageDecoder` 输出的解码数据是正确的，这样 Canvas API 才能正确地绘制图像。
        * **假设输入:** 一个包含 WebP 图像数据的 `ArrayBuffer` 对象。
        * **输出:**  解码后的像素数据，可以用于 Canvas 的 `drawImage()` 方法。
    * **Fetch API:**  可以使用 Fetch API 获取 WebP 图片数据，然后传递给解码器进行解码。测试文件保证了解码器能够处理这些通过网络获取的数据。
    * **Animation API:** 虽然 WebP 本身可以包含动画，但 JavaScript 动画库也可能需要处理解码后的帧数据。

**逻辑推理 (假设输入与输出):**

* **假设输入 (动画 WebP):**  一个包含 3 帧动画的 WebP 文件，其中：
    * 第一帧持续 1000 毫秒，偏移量 (0, 0)，尺寸 (100, 100)。
    * 第二帧持续 500 毫秒，偏移量 (20, 20)，尺寸 (80, 80)。
    * 第三帧持续 2000 毫秒，偏移量 (10, 10)，尺寸 (90, 90)。
* **输出:**  `AnimatedWebPTests` 中的 `verifyAnimationParametersTransparentImage` 类似的测试会验证解码器是否能正确解析这些参数，例如：
    * `decoder->FrameCount()` 返回 3。
    * `decoder->FrameDurationAtIndex(0)` 返回 `base::Milliseconds(1000)`。
    * `decoder->DecodeFrameBufferAtIndex(1)->OriginalFrameRect()` 返回 `SkIRect::MakeXYWH(20, 20, 80, 80)`。

* **假设输入 (静态 WebP):**  一个尺寸为 64x64 的静态 WebP 图片。
* **输出:** `StaticWebPTests` 中的测试会验证：
    * `decoder->FrameCount()` 返回 1。
    * `decoder->DecodeFrameBufferAtIndex(0)->Bitmap().width()` 返回 64。
    * `decoder->DecodeFrameBufferAtIndex(0)->Bitmap().height()` 返回 64。

**用户或编程常见的使用错误:**

1. **提供不完整的 WebP 数据:** 用户或程序可能只获取了 WebP 文件的一部分数据就尝试解码。
    * **例子:** 在网络传输过程中，图片数据尚未完全下载完毕就被传递给解码器。
    * **测试用例:** `AnimatedWebPTests` 中的 `truncatedLastFrame` 和 `truncatedInBetweenFrame` 测试了这种情况，预期解码器会返回部分解码状态 (`ImageFrame::kFramePartial`) 并标记解码失败。

2. **提供损坏的 WebP 文件:**  用户或程序可能提供了内容被破坏的 WebP 文件。
    * **例子:** 文件在存储或传输过程中发生错误。
    * **测试用例:** `AnimatedWebPTests` 中的 `invalidImages` 和 `StaticWebPTests` 中的 `truncatedImage` 测试了这种情况，预期解码器会返回错误，并且可能无法获取帧数或解码帧数据。

3. **不正确的解码器使用顺序:**  虽然这个测试文件主要是测试解码器本身，但开发者在使用 `WEBPImageDecoder` 时，可能会错误地调用其方法。
    * **例子:**  在 `SetData()` 之前就尝试调用 `FrameCount()` 或 `DecodeFrameBufferAtIndex()`。
    * **虽然这个测试文件没有直接测试使用顺序，但它通过不同的测试用例覆盖了 `SetData()`, `FrameCount()`, `DecodeFrameBufferAtIndex()` 等方法的调用，隐含地验证了在不同状态下的行为。**

4. **内存管理错误 (超出此文件范围，但与解码器使用相关):**  虽然 `WEBPImageDecoder` 负责解码，但调用者可能需要管理解码后图像数据的内存。不当的内存管理会导致崩溃或其他问题。

总而言之，`webp_image_decoder_test.cc` 是一个至关重要的测试文件，它确保了 Blink 引擎能够正确、高效、健壮地处理 WebP 图像，这直接影响了网页内容的正确显示和用户体验。

Prompt: 
```
这是目录为blink/renderer/platform/image-decoders/webp/webp_image_decoder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/image-decoders/webp/webp_image_decoder.h"

#include <memory>

#include "base/metrics/histogram_base.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/time/time.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/web_data.h"
#include "third_party/blink/renderer/platform/image-decoders/image_decoder_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

struct AnimParam {
  int x_offset, y_offset, width, height;
  ImageFrame::DisposalMethod disposal_method;
  ImageFrame::AlphaBlendSource alpha_blend_source;
  base::TimeDelta duration;
  bool has_alpha;
};

std::unique_ptr<ImageDecoder> CreateWEBPDecoder(
    ImageDecoder::AlphaOption alpha_option) {
  return std::make_unique<WEBPImageDecoder>(
      alpha_option, ColorBehavior::kTransformToSRGB,
      ImageDecoder::kNoDecodedImageByteLimit);
}

std::unique_ptr<ImageDecoder> CreateWEBPDecoder() {
  return CreateWEBPDecoder(ImageDecoder::kAlphaNotPremultiplied);
}

// If 'parse_error_expected' is true, error is expected during parse
// (FrameCount() call); else error is expected during decode
// (FrameBufferAtIndex() call).
void TestInvalidImage(const char* webp_file, bool parse_error_expected) {
  std::unique_ptr<ImageDecoder> decoder = CreateWEBPDecoder();

  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(webp_file);
  ASSERT_TRUE(data.get());
  decoder->SetData(data.get(), true);

  if (parse_error_expected) {
    EXPECT_EQ(0u, decoder->FrameCount());
    EXPECT_FALSE(decoder->DecodeFrameBufferAtIndex(0));
  } else {
    EXPECT_GT(decoder->FrameCount(), 0u);
    ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(0);
    ASSERT_TRUE(frame);
    EXPECT_EQ(ImageFrame::kFramePartial, frame->GetStatus());
  }
  EXPECT_EQ(kAnimationLoopOnce, decoder->RepetitionCount());
  EXPECT_TRUE(decoder->Failed());
}

void TestWebPBppHistogram(const char* image_name,
                          const char* histogram_name = nullptr,
                          base::HistogramBase::Sample sample = 0) {
  TestBppHistogram(CreateWEBPDecoder, "WebP", image_name, histogram_name,
                   sample);
}

}  // anonymous namespace

TEST(AnimatedWebPTests, uniqueGenerationIDs) {
  std::unique_ptr<ImageDecoder> decoder = CreateWEBPDecoder();

  scoped_refptr<SharedBuffer> data =
      ReadFileToSharedBuffer("/images/resources/webp-animated.webp");
  ASSERT_TRUE(data.get());
  decoder->SetData(data.get(), true);

  ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(0);
  uint32_t generation_id0 = frame->Bitmap().getGenerationID();
  frame = decoder->DecodeFrameBufferAtIndex(1);
  uint32_t generation_id1 = frame->Bitmap().getGenerationID();

  EXPECT_TRUE(generation_id0 != generation_id1);
}

TEST(AnimatedWebPTests, verifyAnimationParametersTransparentImage) {
  std::unique_ptr<ImageDecoder> decoder = CreateWEBPDecoder();
  EXPECT_EQ(kAnimationLoopOnce, decoder->RepetitionCount());

  scoped_refptr<SharedBuffer> data =
      ReadFileToSharedBuffer("/images/resources/webp-animated.webp");
  ASSERT_TRUE(data.get());
  decoder->SetData(data.get(), true);

  const int kCanvasWidth = 11;
  const int kCanvasHeight = 29;
  const AnimParam kFrameParameters[] = {
      {0, 0, 11, 29, ImageFrame::kDisposeKeep,
       ImageFrame::kBlendAtopPreviousFrame, base::Milliseconds(1000), true},
      {2, 10, 7, 17, ImageFrame::kDisposeKeep,
       ImageFrame::kBlendAtopPreviousFrame, base::Milliseconds(500), true},
      {2, 2, 7, 16, ImageFrame::kDisposeKeep,
       ImageFrame::kBlendAtopPreviousFrame, base::Milliseconds(1000), true},
  };

  for (size_t i = 0; i < std::size(kFrameParameters); ++i) {
    const ImageFrame* const frame = decoder->DecodeFrameBufferAtIndex(i);
    EXPECT_EQ(ImageFrame::kFrameComplete, frame->GetStatus());
    EXPECT_EQ(kCanvasWidth, frame->Bitmap().width());
    EXPECT_EQ(kCanvasHeight, frame->Bitmap().height());
    EXPECT_EQ(kFrameParameters[i].x_offset, frame->OriginalFrameRect().x());
    EXPECT_EQ(kFrameParameters[i].y_offset, frame->OriginalFrameRect().y());
    EXPECT_EQ(kFrameParameters[i].width, frame->OriginalFrameRect().width());
    EXPECT_EQ(kFrameParameters[i].height, frame->OriginalFrameRect().height());
    EXPECT_EQ(kFrameParameters[i].disposal_method, frame->GetDisposalMethod());
    EXPECT_EQ(kFrameParameters[i].alpha_blend_source,
              frame->GetAlphaBlendSource());
    EXPECT_EQ(kFrameParameters[i].duration, frame->Duration());
    EXPECT_EQ(kFrameParameters[i].has_alpha, frame->HasAlpha());
  }

  EXPECT_EQ(std::size(kFrameParameters), decoder->FrameCount());
  EXPECT_EQ(kAnimationLoopInfinite, decoder->RepetitionCount());
}

TEST(AnimatedWebPTests,
     verifyAnimationParametersOpaqueFramesTransparentBackground) {
  std::unique_ptr<ImageDecoder> decoder = CreateWEBPDecoder();
  EXPECT_EQ(kAnimationLoopOnce, decoder->RepetitionCount());

  scoped_refptr<SharedBuffer> data =
      ReadFileToSharedBuffer("/images/resources/webp-animated-opaque.webp");
  ASSERT_TRUE(data.get());
  decoder->SetData(data.get(), true);

  const int kCanvasWidth = 94;
  const int kCanvasHeight = 87;
  const AnimParam kFrameParameters[] = {
      {4, 10, 33, 32, ImageFrame::kDisposeOverwriteBgcolor,
       ImageFrame::kBlendAtopPreviousFrame, base::Milliseconds(1000), true},
      {34, 30, 33, 32, ImageFrame::kDisposeOverwriteBgcolor,
       ImageFrame::kBlendAtopPreviousFrame, base::Milliseconds(1000), true},
      {62, 50, 32, 32, ImageFrame::kDisposeOverwriteBgcolor,
       ImageFrame::kBlendAtopPreviousFrame, base::Milliseconds(1000), true},
      {10, 54, 32, 33, ImageFrame::kDisposeOverwriteBgcolor,
       ImageFrame::kBlendAtopPreviousFrame, base::Milliseconds(1000), true},
  };

  for (size_t i = 0; i < std::size(kFrameParameters); ++i) {
    const ImageFrame* const frame = decoder->DecodeFrameBufferAtIndex(i);
    EXPECT_EQ(ImageFrame::kFrameComplete, frame->GetStatus());
    EXPECT_EQ(kCanvasWidth, frame->Bitmap().width());
    EXPECT_EQ(kCanvasHeight, frame->Bitmap().height());
    EXPECT_EQ(kFrameParameters[i].x_offset, frame->OriginalFrameRect().x());
    EXPECT_EQ(kFrameParameters[i].y_offset, frame->OriginalFrameRect().y());
    EXPECT_EQ(kFrameParameters[i].width, frame->OriginalFrameRect().width());
    EXPECT_EQ(kFrameParameters[i].height, frame->OriginalFrameRect().height());
    EXPECT_EQ(kFrameParameters[i].disposal_method, frame->GetDisposalMethod());
    EXPECT_EQ(kFrameParameters[i].alpha_blend_source,
              frame->GetAlphaBlendSource());
    EXPECT_EQ(kFrameParameters[i].duration, frame->Duration());
    EXPECT_EQ(kFrameParameters[i].has_alpha, frame->HasAlpha());
  }

  EXPECT_EQ(std::size(kFrameParameters), decoder->FrameCount());
  EXPECT_EQ(kAnimationLoopInfinite, decoder->RepetitionCount());
}

TEST(AnimatedWebPTests, verifyAnimationParametersBlendOverwrite) {
  std::unique_ptr<ImageDecoder> decoder = CreateWEBPDecoder();
  EXPECT_EQ(kAnimationLoopOnce, decoder->RepetitionCount());

  scoped_refptr<SharedBuffer> data =
      ReadFileToSharedBuffer("/images/resources/webp-animated-no-blend.webp");
  ASSERT_TRUE(data.get());
  decoder->SetData(data.get(), true);

  const int kCanvasWidth = 94;
  const int kCanvasHeight = 87;
  const AnimParam kFrameParameters[] = {
      {4, 10, 33, 32, ImageFrame::kDisposeOverwriteBgcolor,
       ImageFrame::kBlendAtopBgcolor, base::Milliseconds(1000), true},
      {34, 30, 33, 32, ImageFrame::kDisposeOverwriteBgcolor,
       ImageFrame::kBlendAtopBgcolor, base::Milliseconds(1000), true},
      {62, 50, 32, 32, ImageFrame::kDisposeOverwriteBgcolor,
       ImageFrame::kBlendAtopBgcolor, base::Milliseconds(1000), true},
      {10, 54, 32, 33, ImageFrame::kDisposeOverwriteBgcolor,
       ImageFrame::kBlendAtopBgcolor, base::Milliseconds(1000), true},
  };

  for (size_t i = 0; i < std::size(kFrameParameters); ++i) {
    const ImageFrame* const frame = decoder->DecodeFrameBufferAtIndex(i);
    EXPECT_EQ(ImageFrame::kFrameComplete, frame->GetStatus());
    EXPECT_EQ(kCanvasWidth, frame->Bitmap().width());
    EXPECT_EQ(kCanvasHeight, frame->Bitmap().height());
    EXPECT_EQ(kFrameParameters[i].x_offset, frame->OriginalFrameRect().x());
    EXPECT_EQ(kFrameParameters[i].y_offset, frame->OriginalFrameRect().y());
    EXPECT_EQ(kFrameParameters[i].width, frame->OriginalFrameRect().width());
    EXPECT_EQ(kFrameParameters[i].height, frame->OriginalFrameRect().height());
    EXPECT_EQ(kFrameParameters[i].disposal_method, frame->GetDisposalMethod());
    EXPECT_EQ(kFrameParameters[i].alpha_blend_source,
              frame->GetAlphaBlendSource());
    EXPECT_EQ(kFrameParameters[i].duration, frame->Duration());
    EXPECT_EQ(kFrameParameters[i].has_alpha, frame->HasAlpha());
  }

  EXPECT_EQ(std::size(kFrameParameters), decoder->FrameCount());
  EXPECT_EQ(kAnimationLoopInfinite, decoder->RepetitionCount());
}

TEST(AnimatedWebPTests, parseAndDecodeByteByByte) {
  TestByteByByteDecode(&CreateWEBPDecoder,
                       "/images/resources/webp-animated.webp", 3u,
                       kAnimationLoopInfinite);
  TestByteByByteDecode(&CreateWEBPDecoder,
                       "/images/resources/webp-animated-icc-xmp.webp", 13u,
                       31999);
}

TEST(AnimatedWebPTests, invalidImages) {
  // ANMF chunk size is smaller than ANMF header size.
  TestInvalidImage("/images/resources/invalid-animated-webp.webp", true);
  // One of the frame rectangles extends outside the image boundary.
  TestInvalidImage("/images/resources/invalid-animated-webp3.webp", true);
}

TEST(AnimatedWebPTests, truncatedLastFrame) {
  std::unique_ptr<ImageDecoder> decoder = CreateWEBPDecoder();

  scoped_refptr<SharedBuffer> data =
      ReadFileToSharedBuffer("/images/resources/invalid-animated-webp2.webp");
  ASSERT_TRUE(data.get());
  decoder->SetData(data.get(), true);

  size_t frame_count = 8;
  EXPECT_EQ(frame_count, decoder->FrameCount());
  ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(0);
  ASSERT_TRUE(frame);
  EXPECT_EQ(ImageFrame::kFrameComplete, frame->GetStatus());
  EXPECT_FALSE(decoder->Failed());
  frame = decoder->DecodeFrameBufferAtIndex(frame_count - 1);
  ASSERT_TRUE(frame);
  EXPECT_EQ(ImageFrame::kFramePartial, frame->GetStatus());
  EXPECT_TRUE(decoder->Failed());
  frame = decoder->DecodeFrameBufferAtIndex(0);
  ASSERT_TRUE(frame);
  EXPECT_EQ(ImageFrame::kFrameComplete, frame->GetStatus());
}

TEST(AnimatedWebPTests, truncatedInBetweenFrame) {
  std::unique_ptr<ImageDecoder> decoder = CreateWEBPDecoder();

  const Vector<char> full_data =
      ReadFile("/images/resources/invalid-animated-webp4.webp");
  scoped_refptr<SharedBuffer> data =
      SharedBuffer::Create(full_data.data(), full_data.size() - 1);
  decoder->SetData(data.get(), false);

  ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(1);
  ASSERT_TRUE(frame);
  EXPECT_EQ(ImageFrame::kFrameComplete, frame->GetStatus());
  frame = decoder->DecodeFrameBufferAtIndex(2);
  ASSERT_TRUE(frame);
  EXPECT_EQ(ImageFrame::kFramePartial, frame->GetStatus());
  EXPECT_TRUE(decoder->Failed());
}

// Tests for a crash that used to happen for a specific file with specific
// sequence of method calls.
TEST(AnimatedWebPTests, reproCrash) {
  std::unique_ptr<ImageDecoder> decoder = CreateWEBPDecoder();

  const Vector<char> full_data =
      ReadFile("/images/resources/invalid_vp8_vp8x.webp");
  scoped_refptr<SharedBuffer> full_data_buffer =
      SharedBuffer::Create(full_data);

  // Parse partial data up to which error in bitstream is not detected.
  const size_t kPartialSize = 32768;
  ASSERT_GT(full_data.size(), kPartialSize);
  scoped_refptr<SharedBuffer> data =
      SharedBuffer::Create(full_data.data(), kPartialSize);
  decoder->SetData(data.get(), false);
  EXPECT_EQ(1u, decoder->FrameCount());
  ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(0);
  ASSERT_TRUE(frame);
  EXPECT_EQ(ImageFrame::kFramePartial, frame->GetStatus());
  EXPECT_FALSE(decoder->Failed());

  // Parse full data now. The error in bitstream should now be detected.
  decoder->SetData(full_data_buffer.get(), true);
  EXPECT_EQ(1u, decoder->FrameCount());
  frame = decoder->DecodeFrameBufferAtIndex(0);
  ASSERT_TRUE(frame);
  EXPECT_EQ(ImageFrame::kFramePartial, frame->GetStatus());
  EXPECT_EQ(kAnimationLoopOnce, decoder->RepetitionCount());
  EXPECT_TRUE(decoder->Failed());
}

TEST(AnimatedWebPTests, progressiveDecode) {
  TestProgressiveDecoding(&CreateWEBPDecoder,
                          "/images/resources/webp-animated.webp");
}

TEST(AnimatedWebPTests, frameIsCompleteAndDuration) {
  std::unique_ptr<ImageDecoder> decoder = CreateWEBPDecoder();

  const Vector<char> data = ReadFile("/images/resources/webp-animated.webp");
  scoped_refptr<SharedBuffer> data_buffer = SharedBuffer::Create(data);

  ASSERT_GE(data.size(), 10u);
  scoped_refptr<SharedBuffer> temp_data =
      SharedBuffer::Create(data.data(), data.size() - 10);
  decoder->SetData(temp_data.get(), false);

  EXPECT_EQ(2u, decoder->FrameCount());
  EXPECT_FALSE(decoder->Failed());
  EXPECT_TRUE(decoder->FrameIsReceivedAtIndex(0));
  EXPECT_EQ(base::Milliseconds(1000), decoder->FrameDurationAtIndex(0));
  EXPECT_TRUE(decoder->FrameIsReceivedAtIndex(1));
  EXPECT_EQ(base::Milliseconds(500), decoder->FrameDurationAtIndex(1));

  decoder->SetData(data_buffer.get(), true);
  EXPECT_EQ(3u, decoder->FrameCount());
  EXPECT_TRUE(decoder->FrameIsReceivedAtIndex(0));
  EXPECT_EQ(base::Milliseconds(1000), decoder->FrameDurationAtIndex(0));
  EXPECT_TRUE(decoder->FrameIsReceivedAtIndex(1));
  EXPECT_EQ(base::Milliseconds(500), decoder->FrameDurationAtIndex(1));
  EXPECT_TRUE(decoder->FrameIsReceivedAtIndex(2));
  EXPECT_EQ(base::Milliseconds(1000), decoder->FrameDurationAtIndex(2));
}

TEST(AnimatedWebPTests, updateRequiredPreviousFrameAfterFirstDecode) {
  TestUpdateRequiredPreviousFrameAfterFirstDecode(
      &CreateWEBPDecoder, "/images/resources/webp-animated.webp");
}

TEST(AnimatedWebPTests, randomFrameDecode) {
  TestRandomFrameDecode(&CreateWEBPDecoder,
                        "/images/resources/webp-animated.webp");
  TestRandomFrameDecode(&CreateWEBPDecoder,
                        "/images/resources/webp-animated-opaque.webp");
  TestRandomFrameDecode(&CreateWEBPDecoder,
                        "/images/resources/webp-animated-large.webp");
  TestRandomFrameDecode(&CreateWEBPDecoder,
                        "/images/resources/webp-animated-icc-xmp.webp");
}

TEST(AnimatedWebPTests, randomDecodeAfterClearFrameBufferCache) {
  TestRandomDecodeAfterClearFrameBufferCache(
      &CreateWEBPDecoder, "/images/resources/webp-animated.webp");
  TestRandomDecodeAfterClearFrameBufferCache(
      &CreateWEBPDecoder, "/images/resources/webp-animated-opaque.webp");
  TestRandomDecodeAfterClearFrameBufferCache(
      &CreateWEBPDecoder, "/images/resources/webp-animated-large.webp");
  TestRandomDecodeAfterClearFrameBufferCache(
      &CreateWEBPDecoder, "/images/resources/webp-animated-icc-xmp.webp");
}

TEST(AnimatedWebPTests, decodeAfterReallocatingData) {
  TestDecodeAfterReallocatingData(&CreateWEBPDecoder,
                                  "/images/resources/webp-animated.webp");
  TestDecodeAfterReallocatingData(
      &CreateWEBPDecoder, "/images/resources/webp-animated-icc-xmp.webp");
}

TEST(AnimatedWebPTests, alphaBlending) {
  TestAlphaBlending(&CreateWEBPDecoder, "/images/resources/webp-animated.webp");
  TestAlphaBlending(&CreateWEBPDecoder,
                    "/images/resources/webp-animated-semitransparent1.webp");
  TestAlphaBlending(&CreateWEBPDecoder,
                    "/images/resources/webp-animated-semitransparent2.webp");
  TestAlphaBlending(&CreateWEBPDecoder,
                    "/images/resources/webp-animated-semitransparent3.webp");
  TestAlphaBlending(&CreateWEBPDecoder,
                    "/images/resources/webp-animated-semitransparent4.webp");
}

TEST(AnimatedWebPTests, isSizeAvailable) {
  TestByteByByteSizeAvailable(&CreateWEBPDecoder,
                              "/images/resources/webp-animated.webp", 142u,
                              false, kAnimationLoopInfinite);
  // FIXME: Add color profile support for animated webp images.
  TestByteByByteSizeAvailable(&CreateWEBPDecoder,
                              "/images/resources/webp-animated-icc-xmp.webp",
                              1404u, false, 31999);
}

TEST(AnimatedWEBPTests, clearCacheExceptFrameWithAncestors) {
  std::unique_ptr<ImageDecoder> decoder = CreateWEBPDecoder();

  scoped_refptr<SharedBuffer> full_data =
      ReadFileToSharedBuffer("/images/resources/webp-animated.webp");
  ASSERT_TRUE(full_data.get());
  decoder->SetData(full_data.get(), true);

  ASSERT_EQ(3u, decoder->FrameCount());
  // We need to store pointers to the image frames, since calling
  // FrameBufferAtIndex will decode the frame if it is not FrameComplete,
  // and we want to read the status of the frame without decoding it again.
  ImageFrame* buffers[3];
  size_t buffer_sizes[3];
  for (size_t i = 0; i < decoder->FrameCount(); i++) {
    buffers[i] = decoder->DecodeFrameBufferAtIndex(i);
    ASSERT_EQ(ImageFrame::kFrameComplete, buffers[i]->GetStatus());
    buffer_sizes[i] = decoder->FrameBytesAtIndex(i);
  }

  // Explicitly set the required previous frame for the frames, since this test
  // is designed on this chain. Whether the frames actually depend on each
  // other is not important for this test - ClearCacheExceptFrame just looks at
  // the frame status and the required previous frame.
  buffers[1]->SetRequiredPreviousFrameIndex(0);
  buffers[2]->SetRequiredPreviousFrameIndex(1);

  // Clear the cache except for a single frame. All other frames should be
  // cleared to FrameEmpty, since this frame is FrameComplete.
  EXPECT_EQ(buffer_sizes[0] + buffer_sizes[2],
            decoder->ClearCacheExceptFrame(1));
  EXPECT_EQ(ImageFrame::kFrameEmpty, buffers[0]->GetStatus());
  EXPECT_EQ(ImageFrame::kFrameComplete, buffers[1]->GetStatus());
  EXPECT_EQ(ImageFrame::kFrameEmpty, buffers[2]->GetStatus());

  // Verify that the required previous frame is also preserved if the provided
  // frame is not FrameComplete. The simulated situation is:
  //
  // Frame 0          <---------    Frame 1         <---------    Frame 2
  // FrameComplete    depends on    FrameComplete   depends on    FramePartial
  //
  // The expected outcome is that frame 1 and frame 2 are preserved, since
  // frame 1 is necessary to fully decode frame 2.
  for (size_t i = 0; i < decoder->FrameCount(); i++) {
    ASSERT_EQ(ImageFrame::kFrameComplete,
              decoder->DecodeFrameBufferAtIndex(i)->GetStatus());
  }
  buffers[2]->SetStatus(ImageFrame::kFramePartial);
  EXPECT_EQ(buffer_sizes[0], decoder->ClearCacheExceptFrame(2));
  EXPECT_EQ(ImageFrame::kFrameEmpty, buffers[0]->GetStatus());
  EXPECT_EQ(ImageFrame::kFrameComplete, buffers[1]->GetStatus());
  EXPECT_EQ(ImageFrame::kFramePartial, buffers[2]->GetStatus());

  // Verify that the nearest FrameComplete required frame is preserved if
  // earlier required frames in the ancestor list are not FrameComplete. The
  // simulated situation is:
  //
  // Frame 0          <---------    Frame 1      <---------    Frame 2
  // FrameComplete    depends on    FrameEmpty   depends on    FramePartial
  //
  // The expected outcome is that frame 0 and frame 2 are preserved. Frame 2
  // should be preserved since it is the frame passed to ClearCacheExceptFrame.
  // Frame 0 should be preserved since it is the nearest FrameComplete ancestor.
  // Thus, since frame 1 is FrameEmpty, no data is cleared in this case.
  for (size_t i = 0; i < decoder->FrameCount(); i++) {
    ASSERT_EQ(ImageFrame::kFrameComplete,
              decoder->DecodeFrameBufferAtIndex(i)->GetStatus());
  }
  buffers[1]->SetStatus(ImageFrame::kFrameEmpty);
  buffers[2]->SetStatus(ImageFrame::kFramePartial);
  EXPECT_EQ(0u, decoder->ClearCacheExceptFrame(2));
  EXPECT_EQ(ImageFrame::kFrameComplete, buffers[0]->GetStatus());
  EXPECT_EQ(ImageFrame::kFrameEmpty, buffers[1]->GetStatus());
  EXPECT_EQ(ImageFrame::kFramePartial, buffers[2]->GetStatus());
}

TEST(StaticWebPTests, truncatedImage) {
  // VP8 data is truncated.
  TestInvalidImage("/images/resources/truncated.webp", false);
  // Chunk size in RIFF header doesn't match the file size.
  TestInvalidImage("/images/resources/truncated2.webp", true);
}

// Regression test for a bug where some valid images were failing to decode
// incrementally.
TEST(StaticWebPTests, incrementalDecode) {
  TestByteByByteDecode(&CreateWEBPDecoder,
                       "/images/resources/crbug.364830.webp", 1u,
                       kAnimationNone);
  TestByteByByteDecode(&CreateWEBPDecoder,
                       "/images/resources/size-failure.b186640109.webp", 1u,
                       kAnimationNone);
}

TEST(StaticWebPTests, isSizeAvailable) {
  TestByteByByteSizeAvailable(&CreateWEBPDecoder,
                              "/images/resources/webp-color-profile-lossy.webp",
                              520u, true, kAnimationNone);
  TestByteByByteSizeAvailable(&CreateWEBPDecoder, "/images/resources/test.webp",
                              30u, false, kAnimationNone);
  TestByteByByteSizeAvailable(&CreateWEBPDecoder,
                              "/images/resources/size-failure.b186640109.webp",
                              25u, false, kAnimationNone);
}

TEST(StaticWebPTests, notAnimated) {
  std::unique_ptr<ImageDecoder> decoder = CreateWEBPDecoder();
  scoped_refptr<SharedBuffer> data =
      ReadFileToSharedBuffer("/images/resources/webp-color-profile-lossy.webp");
  ASSERT_TRUE(data.get());
  decoder->SetData(data.get(), true);
  EXPECT_EQ(1u, decoder->FrameCount());
  EXPECT_EQ(kAnimationNone, decoder->RepetitionCount());
}

TEST(StaticWebPTests, bppHistogramSmall) {
  constexpr int kImageArea = 800 * 800;  // = 640000
  constexpr int kFileSize = 19436;
  constexpr int kSample =
      (kFileSize * 100 * 8 + kImageArea / 2) / kImageArea;  // = 24
  TestWebPBppHistogram("/images/resources/webp-color-profile-lossy.webp",
                       "Blink.DecodedImage.WebPDensity.Count.0.7MP", kSample);
}

TEST(StaticWebPTests, bppHistogramSmall3x3) {
  // The centi bpp = 68 * 100 * 8 / (3 * 3) ~= 6044, which is greater than the
  // histogram's max value (1000), so this sample goes into the overflow bucket.
  constexpr int kSample = 1000;
  TestWebPBppHistogram("/images/resources/red3x3-lossy.webp",
                       "Blink.DecodedImage.WebPDensity.Count.0.1MP", kSample);
}

TEST(StaticWebPTests, bppHistogramSmall900000) {
  constexpr int kImageArea = 1200 * 750;  // = 900000
  constexpr int kFileSize = 11180;
  constexpr int kSample =
      (kFileSize * 100 * 8 + kImageArea / 2) / kImageArea;  // = 10
  TestWebPBppHistogram("/images/resources/peach_900000.webp",
                       "Blink.DecodedImage.WebPDensity.Count.0.9MP", kSample);
}

TEST(StaticWebPTests, bppHistogramBig) {
  constexpr int kImageArea = 3024 * 4032;  // = 12192768
  constexpr int kFileSize = 87822;
  constexpr int kSample =
      (kFileSize * 100 * 8 + kImageArea / 2) / kImageArea;  // = 6
  TestWebPBppHistogram("/images/resources/bee.webp",
                       "Blink.DecodedImage.WebPDensity.Count.13MP", kSample);
}

TEST(StaticWebPTests, bppHistogramBig13000000) {
  constexpr int kImageArea = 4000 * 3250;  // = 13000000
  constexpr int kFileSize = 58402;
  constexpr int kSample =
      (kFileSize * 100 * 8 + kImageArea / 2) / kImageArea;  // = 4
  TestWebPBppHistogram("/images/resources/peach_13000000.webp",
                       "Blink.DecodedImage.WebPDensity.Count.13MP", kSample);
}

TEST(StaticWebPTests, bppHistogramHuge) {
  constexpr int kImageArea = 4624 * 3472;  // = 16054528
  constexpr int kFileSize = 66594;
  constexpr int kSample =
      (kFileSize * 100 * 8 + kImageArea / 2) / kImageArea;  // = 3
  TestWebPBppHistogram("/images/resources/peach.webp",
                       "Blink.DecodedImage.WebPDensity.Count.14+MP", kSample);
}

TEST(StaticWebPTests, bppHistogramHuge13000002) {
  constexpr int kImageArea = 3961 * 3282;  // = 13000002
  constexpr int kFileSize = 53968;
  constexpr int kSample =
      (kFileSize * 100 * 8 + kImageArea / 2) / kImageArea;  // = 3
  TestWebPBppHistogram("/images/resources/peach_13000002.webp",
                       "Blink.DecodedImage.WebPDensity.Count.14+MP", kSample);
}

// Although parsing of the image succeeds, decoding of the image fails, so the
// test should not emit to any bpp histogram.
TEST(StaticWebPTests, bppHistogramInvalid) {
  base::HistogramTester histogram_tester;
  std::unique_ptr<ImageDecoder> decoder = CreateWEBPDecoder();
  decoder->SetData(ReadFileToSharedBuffer("/images/resources/truncated.webp"),
                   true);
  ASSERT_TRUE(decoder->IsSizeAvailable());
  EXPECT_FALSE(decoder->Failed());
  EXPECT_EQ(decoder->FrameCount(), 1u);
  ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(0);
  ASSERT_TRUE(frame);
  EXPECT_NE(ImageFrame::kFrameComplete, frame->GetStatus());
  EXPECT_TRUE(decoder->Failed());
  const base::HistogramTester::CountsMap empty_counts;
  EXPECT_THAT(histogram_tester.GetTotalCountsForPrefix(
                  "Blink.DecodedImage.WebPDensity.Count."),
              testing::ContainerEq(empty_counts));
}

TEST(StaticWebPTests, bppHistogramLossless) {
  TestWebPBppHistogram("/images/resources/red3x3-lossless.webp");
}

TEST(StaticWebPTests, bppHistogramAlpha) {
  TestWebPBppHistogram("/images/resources/webp-color-profile-lossy-alpha.webp");
}

TEST(StaticWebPTests, bppHistogramAnimated) {
  TestWebPBppHistogram("/images/resources/webp-animated-opaque.webp");
}

}  // namespace blink

"""

```