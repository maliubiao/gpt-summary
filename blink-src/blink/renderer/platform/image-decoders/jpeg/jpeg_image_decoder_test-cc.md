Response:
My thinking process to analyze the C++ test file and generate the explanation involved these steps:

1. **Understand the Goal:** The primary goal is to explain the functionality of the `jpeg_image_decoder_test.cc` file and relate it to web technologies (JavaScript, HTML, CSS) where possible. It also needs to cover logical reasoning, assumptions, and common user errors.

2. **Identify the Core Functionality:**  The filename and the `#include` statements immediately indicate this file is for testing the `JPEGImageDecoder` class. The `TEST` macros confirm this. Therefore, the core function is *testing the JPEG image decoding capabilities* of the Blink rendering engine.

3. **Break Down the Test Cases:** I went through each `TEST` function to understand what specific aspect of the decoder it was testing. I categorized them roughly as follows:
    * **Basic Decoding:**  `tooBig`, basic downsampling (`downsampleImageSizeMultipleOf8`, `downsampleImageSizeNotMultipleOf8`), upsampling (`upsample`).
    * **YUV Decoding:** `yuv`, `missingEoi`.
    * **Byte-by-Byte Decoding:**  Testing progressive and baseline JPEG decoding in a more controlled, incremental manner (`byteByByteBaselineJPEGWithColorProfileAndRestartMarkers`, `byteByByteProgressiveJPEG`, `byteByByteRGBJPEGWithAdobeMarkers`).
    * **Error Handling and Edge Cases:** `manyProgressiveScans`, `exifWithInitialIfdLast`.
    * **Supported Sizes/Downscaling Logic:** `SupportedSizesSquare`, `SupportedSizesRectangle`, `SupportedSizesRectangleNotMultipleOfMCUIfMemoryBound`, `SupportedSizesRectangleNotMultipleOfMCU`, `SupportedSizesTruncatedIfMemoryBound`, `SupportedScaleNumeratorBound`.
    * **Color Space Handling:** `YuvDecode`, `RgbDecode` (using the `ColorSpaceTest` parameterized test).
    * **Partial Data Handling:** `PartialDataWithoutSize`, `PartialRgbDecodeBlocksYuvDecoding`.
    * **Gainmap Support:** `Gainmap`.
    * **Performance Metrics (Histograms):** `BppHistogramSmall`, `BppHistogramSmall16x16`, etc., and `BppHistogramInvalid`, `BppHistogramGrayscale`.

4. **Relate to Web Technologies:**  This is a crucial step. I considered *where* JPEG decoding fits within the browser's rendering pipeline.
    * **HTML `<img>` tag:** The most direct connection. Browsers need to decode JPEGs to display them.
    * **CSS `background-image`:**  Similar to `<img>`, CSS properties can use JPEG images.
    * **Canvas API:** JavaScript can use the Canvas API to load and manipulate image data, including JPEGs. This involves decoding.
    * **Fetch API and `createImageBitmap`:**  More modern APIs in JavaScript allow for fetching and decoding images.

5. **Construct Examples:** For each relationship identified above, I created simple, illustrative examples using HTML, CSS, and JavaScript to show how the underlying JPEG decoding mechanism is utilized.

6. **Address Logical Reasoning (Assumptions and Input/Output):** For test cases involving specific logic (like downsampling), I tried to articulate the assumptions being made by the test (e.g., a specific downsampling factor) and the expected output (the resulting image dimensions). This often involved looking at the parameters passed to the test functions.

7. **Identify Common User/Programming Errors:**  I thought about what mistakes developers might make when dealing with images in a web context:
    * **Incorrect file paths.**
    * **Assuming specific image formats are supported.**
    * **Not handling decoding errors.**
    * **Memory issues with large images.**
    * **Incorrectly setting image dimensions.**

8. **Structure the Explanation:** I organized the information logically:
    * Start with a high-level summary of the file's purpose.
    * Detail the specific functionalities tested by each test case.
    * Explain the relationship to web technologies with concrete examples.
    * Provide logical reasoning with assumptions and I/O for relevant tests.
    * List common user/programming errors.

9. **Refine and Elaborate:** I reviewed my initial draft and added more details and clarity where needed. For instance, when explaining downsampling, I clarified *why* it's important (performance). For the histogram tests, I explained what they are measuring (bits per pixel).

10. **Use the Provided Code Snippets:** I made sure to reference specific parts of the code (like function names and constants) to make the explanation more concrete and easier to follow.

By following these steps, I aimed to produce a comprehensive and informative explanation of the `jpeg_image_decoder_test.cc` file, addressing all the requirements of the prompt.
这个文件 `jpeg_image_decoder_test.cc` 是 Chromium Blink 引擎中用于测试 `JPEGImageDecoder` 类的单元测试文件。它的主要功能是验证 `JPEGImageDecoder` 类是否能够正确地解码 JPEG 图像，并处理各种边缘情况和错误场景。

以下是该文件列举的功能的详细说明：

**核心功能：JPEG 解码功能测试**

* **基本解码测试:**
    * **`tooBig`:** 测试当尝试解码一个超过内存限制的过大图像时，解码器是否会正确失败。
    * **`downsampleImageSizeMultipleOf8` 和 `downsampleImageSizeNotMultipleOf8`:** 测试解码器在内存限制下能否正确地对图像进行下采样，包括宽高是 8 的倍数和非 8 的倍数的情况。这对于在内存受限的设备上优化性能至关重要。
    * **`upsample`:** 测试解码器是否不允许对图像进行上采样。
    * **`byteByByteBaselineJPEGWithColorProfileAndRestartMarkers`、`byteByByteProgressiveJPEG`、`byteByByteRGBJPEGWithAdobeMarkers`:** 通过逐字节喂入数据的方式测试解码器对不同类型的 JPEG 图像（包括带有颜色配置文件、重启标记、渐进式和带有 Adobe 标记的 RGB JPEG）的解码能力。这种测试方法可以更细致地检测解码过程中的问题。
    * **`manyProgressiveScans`:** 测试解码器处理包含大量渐进式扫描的 JPEG 图像时的行为，防止出现卡死等问题。
    * **`exifWithInitialIfdLast`:** 测试解码器能否正确处理 EXIF 数据，特别是当初始 IFD (Image File Directory) 位于数据末尾的情况，并验证是否能正确提取图像方向和密度校正尺寸。
    * **`PartialDataWithoutSize` 和 `PartialRgbDecodeBlocksYuvDecoding`:** 测试解码器处理不完整 JPEG 数据的情况，验证其能否正确识别数据不完整并在后续接收到完整数据后继续解码。同时测试在部分 RGB 数据解码后是否会阻止 YUV 解码。
    * **`Gainmap`:** 测试解码器是否能够正确解析和提取 JPEG 图像中的 Gainmap 信息，这是一种用于高动态范围 (HDR) 图像的技术。

* **YUV 解码测试:**
    * **`yuv`:** 测试解码器是否能够正确解码为 YUV 颜色空间，这对于视频处理和某些优化场景非常重要。测试了不同采样格式 (4:2:0) 和非交错扫描的 JPEG 图像。
    * **`missingEoi`:** 测试当 JPEG 图像缺少 EOI (End of Image) 标记时，YUV 解码器是否会失败，但仍然能提供可显示的 YUV 数据。

* **颜色空间测试 (`ColorSpaceTest`)**:
    * 通过参数化测试，覆盖了各种 JPEG 颜色空间编码（如灰度、RGB、CMYK、YCCK、YCbCr 等）和色度子采样格式 (4:1:0, 4:1:1, 4:2:0, 4:2:2, 4:4:0, 4:4:4)。测试了在不同颜色空间下，解码器能否成功解码为 RGB 或 YUV。

* **支持的解码尺寸测试:**
    * **`SupportedSizesSquare`、`SupportedSizesRectangle`、`SupportedSizesRectangleNotMultipleOfMCUIfMemoryBound`、`SupportedSizesRectangleNotMultipleOfMCU`、`SupportedSizesTruncatedIfMemoryBound`:** 测试解码器在不同内存限制下，能否正确计算和返回支持的解码尺寸列表。这对于根据可用资源动态选择合适的解码尺寸非常重要。

* **缩放比例计算测试:**
    * **`SupportedScaleNumeratorBound`:** 测试解码器计算期望的缩放比例分子的逻辑，确保在各种情况下都能得到正确的结果。

* **性能指标测试 (直方图):**
    * **`BppHistogramSmall`、`BppHistogramSmall16x16`、`BppHistogramSmall900000`、`BppHistogramBig`、`BppHistogramBig13000000`、`BppHistogramHuge`、`BppHistogramHuge13000002`、`BppHistogramInvalid`、`BppHistogramGrayscale`:** 测试解码器在解码不同大小和类型的 JPEG 图像时，是否会记录正确的每像素比特数 (bits per pixel, BPP) 到直方图中。这些直方图用于性能分析和监控。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`JPEGImageDecoder` 是浏览器渲染引擎内部使用的组件，直接与 JavaScript、HTML 和 CSS 功能相关，因为它负责解码网页中使用的 JPEG 图像。

1. **HTML `<img>` 标签:**
   - 当 HTML 中使用 `<img src="image.jpg">` 标签加载 JPEG 图像时，Blink 引擎会调用 `JPEGImageDecoder` 来解码 `image.jpg` 的数据。
   - **假设输入:**  一个包含有效 JPEG 数据的字节流，对应于 `image.jpg` 文件。
   - **输出:** 解码后的像素数据，用于在页面上渲染图像。

2. **CSS `background-image` 属性:**
   - 当 CSS 中使用 `background-image: url("background.jpg");` 来设置背景图像时，如果 `background.jpg` 是 JPEG 格式，`JPEGImageDecoder` 同样会被调用来解码图像数据。
   - **假设输入:**  一个包含有效 JPEG 数据的字节流，对应于 `background.jpg` 文件。
   - **输出:** 解码后的像素数据，用于绘制元素的背景。

3. **Canvas API (`<canvas>`)**:
   - JavaScript 可以使用 Canvas API 来操作图像数据。例如，可以使用 `drawImage()` 方法将 JPEG 图像绘制到 canvas 上。这背后也涉及到 `JPEGImageDecoder` 的解码过程。
   - **假设输入:**
     - JavaScript 代码：
       ```javascript
       const canvas = document.getElementById('myCanvas');
       const ctx = canvas.getContext('2d');
       const image = new Image();
       image.onload = function() {
         ctx.drawImage(image, 0, 0);
       };
       image.src = 'canvas_image.jpg';
       ```
     - `canvas_image.jpg`: 一个 JPEG 图像文件。
   - **输出:**  解码后的 `canvas_image.jpg` 像素数据被绘制到 canvas 上。

4. **Fetch API 和 `createImageBitmap`:**
   - JavaScript 可以使用 Fetch API 获取图像数据，并使用 `createImageBitmap()` 方法将其解码为 `ImageBitmap` 对象，该对象可以用于 Canvas 或 WebGL。如果获取的是 JPEG 图像，`JPEGImageDecoder` 会参与解码过程。
   - **假设输入:**
     - JavaScript 代码：
       ```javascript
       fetch('fetched_image.jpg')
         .then(response => response.blob())
         .then(blob => createImageBitmap(blob))
         .then(imageBitmap => {
           // 使用 imageBitmap
         });
       ```
     - `fetched_image.jpg`: 一个 JPEG 图像文件。
   - **输出:** 解码后的 `fetched_image.jpg` 像素数据存储在 `imageBitmap` 对象中。

**逻辑推理的假设输入与输出：**

以 `downsampleImageSizeMultipleOf8` 测试为例：

* **假设输入:**
    * JPEG 图像文件 `/images/resources/gracehopper.jpg` (原始尺寸 256x256)。
    * `max_decoded_bytes` 参数设置为不同的值，例如 `40 * 40 * 4`。
* **逻辑推理:**  当 `max_decoded_bytes` 较小时，解码器会尝试进行下采样以减少内存使用。例如，当 `max_decoded_bytes` 限制为足以容纳大约 32x32 图像的字节数时，解码器应该输出一个 32x32 的图像。
* **预期输出:**  `decoder->DecodedSize()` 返回 `gfx::Size(32, 32)`，并且解码后的图像帧的尺寸也是 32x32。

**涉及用户或编程常见的使用错误：**

1. **文件路径错误:**
   - **错误:** 在 HTML 或 CSS 中指定了错误的 JPEG 文件路径，导致浏览器无法找到图像文件，解码器无法接收到有效数据。
   - **例子:** `<img src="imge.jpg">` (typo in filename)。
   - **结果:** 浏览器会显示图像加载失败的占位符。

2. **假设所有图像格式都能解码:**
   - **错误:** 开发者可能错误地假设浏览器能够解码所有类型的图像文件，而没有考虑浏览器支持的格式限制。
   - **例子:**  尝试在 `<img src>` 中使用一个不支持的格式（例如，一个自定义的图像格式）。
   - **结果:** 浏览器无法解码图像，可能显示加载错误。

3. **没有处理解码错误:**
   - **错误:** 在 JavaScript 中使用 Canvas API 或 Fetch API 加载图像时，没有适当处理图像加载失败的情况。
   - **例子:**
     ```javascript
     const image = new Image();
     image.onload = function() {
       // 假设加载成功，直接使用 image
     };
     image.src = 'invalid_image.jpg'; // 文件损坏或不是 JPEG
     ```
   - **结果:**  如果 `invalid_image.jpg` 不是有效的 JPEG 文件，`onload` 事件可能不会触发，或者解码器会报告错误，但 JavaScript 代码没有处理这种情况。

4. **内存限制问题:**
   - **错误:**  尝试解码非常大的 JPEG 图像，而用户的设备内存不足。
   - **例子:**  在移动设备上加载一个几千兆像素的 JPEG 图像。
   - **结果:**  解码过程可能失败，导致图像无法显示，或者导致浏览器崩溃。Blink 的 `JPEGImageDecoder` 试图通过下采样来缓解这个问题，但如果内存限制过于严格，仍然可能失败。

5. **不正确的图像尺寸假设:**
   - **错误:**  在 JavaScript 中操作解码后的图像数据时，错误地假设了图像的尺寸或像素格式。
   - **例子:**  在使用 Canvas API 的 `getImageData()` 方法后，错误地计算像素索引，导致访问越界或颜色错误。

`jpeg_image_decoder_test.cc` 文件通过各种测试用例，确保 `JPEGImageDecoder` 能够健壮地处理这些潜在的错误，并提供可靠的 JPEG 解码功能，从而保证网页上 JPEG 图像的正确显示。

Prompt: 
```
这是目录为blink/renderer/platform/image-decoders/jpeg/jpeg_image_decoder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/platform/image-decoders/jpeg/jpeg_image_decoder.h"

#include <limits>
#include <memory>
#include <string>

#include "base/test/metrics/histogram_tester.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/web_data.h"
#include "third_party/blink/renderer/platform/graphics/bitmap_image_metrics.h"
#include "third_party/blink/renderer/platform/image-decoders/image_animation.h"
#include "third_party/blink/renderer/platform/image-decoders/image_decoder_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"

namespace blink {

static const size_t kLargeEnoughSize = 1000 * 1000;

namespace {

std::unique_ptr<JPEGImageDecoder> CreateJPEGDecoder(size_t max_decoded_bytes) {
  return std::make_unique<JPEGImageDecoder>(
      ImageDecoder::kAlphaNotPremultiplied, ColorBehavior::kTransformToSRGB,
      cc::AuxImage::kDefault, max_decoded_bytes);
}

std::unique_ptr<ImageDecoder> CreateJPEGDecoder() {
  return CreateJPEGDecoder(ImageDecoder::kNoDecodedImageByteLimit);
}

void Downsample(size_t max_decoded_bytes,
                const char* image_file_path,
                const gfx::Size& expected_size) {
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(image_file_path);
  ASSERT_TRUE(data);

  std::unique_ptr<ImageDecoder> decoder = CreateJPEGDecoder(max_decoded_bytes);
  decoder->SetData(data.get(), true);

  ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(0);
  ASSERT_TRUE(frame);
  EXPECT_EQ(expected_size.width(), frame->Bitmap().width());
  EXPECT_EQ(expected_size.height(), frame->Bitmap().height());
  EXPECT_EQ(expected_size, decoder->DecodedSize());
}

void ReadYUV(size_t max_decoded_bytes,
             const char* image_file_path,
             const gfx::Size& expected_y_size,
             const gfx::Size& expected_uv_size,
             const bool expect_decoding_failure = false) {
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(image_file_path);
  ASSERT_TRUE(data);

  std::unique_ptr<JPEGImageDecoder> decoder =
      CreateJPEGDecoder(max_decoded_bytes);
  decoder->SetData(data.get(), true);

  ASSERT_TRUE(decoder->IsSizeAvailable());
  ASSERT_TRUE(decoder->CanDecodeToYUV());

  gfx::Size size = decoder->DecodedSize();

  gfx::Size y_size = decoder->DecodedYUVSize(cc::YUVIndex::kY);
  gfx::Size u_size = decoder->DecodedYUVSize(cc::YUVIndex::kU);
  gfx::Size v_size = decoder->DecodedYUVSize(cc::YUVIndex::kV);

  EXPECT_EQ(size, y_size);
  EXPECT_EQ(u_size, v_size);

  EXPECT_EQ(expected_y_size, y_size);
  EXPECT_EQ(expected_uv_size, u_size);

  wtf_size_t row_bytes[3];
  row_bytes[0] = decoder->DecodedYUVWidthBytes(cc::YUVIndex::kY);
  row_bytes[1] = decoder->DecodedYUVWidthBytes(cc::YUVIndex::kU);
  row_bytes[2] = decoder->DecodedYUVWidthBytes(cc::YUVIndex::kV);

  size_t planes_data_size = row_bytes[0] * y_size.height() +
                            row_bytes[1] * u_size.height() +
                            row_bytes[2] * v_size.height();
  auto planes_data = std::make_unique<char[]>(planes_data_size);

  void* planes[3];
  planes[0] = planes_data.get();
  planes[1] = static_cast<char*>(planes[0]) + row_bytes[0] * y_size.height();
  planes[2] = static_cast<char*>(planes[1]) + row_bytes[1] * u_size.height();

  decoder->SetImagePlanes(
      std::make_unique<ImagePlanes>(planes, row_bytes, kGray_8_SkColorType));

  decoder->DecodeToYUV();

  EXPECT_EQ(expect_decoding_failure, decoder->Failed());
  EXPECT_TRUE(decoder->HasDisplayableYUVData());
}

void TestJpegBppHistogram(const char* image_name,
                          const char* histogram_name = nullptr,
                          base::HistogramBase::Sample sample = 0) {
  TestBppHistogram(CreateJPEGDecoder, "Jpeg", image_name, histogram_name,
                   sample);
}

}  // anonymous namespace

// Tests failure on a too big image.
TEST(JPEGImageDecoderTest, tooBig) {
  std::unique_ptr<ImageDecoder> decoder = CreateJPEGDecoder(100);
  EXPECT_FALSE(decoder->SetSize(10000u, 10000u));
  EXPECT_TRUE(decoder->Failed());
}

// Tests that the JPEG decoder can downsample image whose width and height are
// multiples of 8, to ensure we compute the correct DecodedSize and pass correct
// parameters to libjpeg to output the image with the expected size.
TEST(JPEGImageDecoderTest, downsampleImageSizeMultipleOf8) {
  const char* jpeg_file = "/images/resources/gracehopper.jpg";  // 256x256

  // 1/8 downsample.
  Downsample(40 * 40 * 4, jpeg_file, gfx::Size(32, 32));

  // 2/8 downsample.
  Downsample(70 * 70 * 4, jpeg_file, gfx::Size(64, 64));

  // 3/8 downsample.
  Downsample(100 * 100 * 4, jpeg_file, gfx::Size(96, 96));

  // 4/8 downsample.
  Downsample(130 * 130 * 4, jpeg_file, gfx::Size(128, 128));

  // 5/8 downsample.
  Downsample(170 * 170 * 4, jpeg_file, gfx::Size(160, 160));

  // 6/8 downsample.
  Downsample(200 * 200 * 4, jpeg_file, gfx::Size(192, 192));

  // 7/8 downsample.
  Downsample(230 * 230 * 4, jpeg_file, gfx::Size(224, 224));
}

// Tests that JPEG decoder can downsample image whose width and height are not
// multiple of 8. Ensures that we round using the same algorithm as libjpeg.
TEST(JPEGImageDecoderTest, downsampleImageSizeNotMultipleOf8) {
  const char* jpeg_file = "/images/resources/icc-v2-gbr.jpg";  // 275x207

  // 1/8 downsample.
  Downsample(40 * 40 * 4, jpeg_file, gfx::Size(35, 26));

  // 2/8 downsample.
  Downsample(70 * 70 * 4, jpeg_file, gfx::Size(69, 52));

  // 3/8 downsample.
  Downsample(100 * 100 * 4, jpeg_file, gfx::Size(104, 78));

  // 4/8 downsample.
  Downsample(130 * 130 * 4, jpeg_file, gfx::Size(138, 104));

  // 5/8 downsample.
  Downsample(170 * 170 * 4, jpeg_file, gfx::Size(172, 130));

  // 6/8 downsample.
  Downsample(200 * 200 * 4, jpeg_file, gfx::Size(207, 156));

  // 7/8 downsample.
  Downsample(230 * 230 * 4, jpeg_file, gfx::Size(241, 182));
}

// Tests that upsampling is not allowed.
TEST(JPEGImageDecoderTest, upsample) {
  const char* jpeg_file = "/images/resources/gracehopper.jpg";  // 256x256
  Downsample(kLargeEnoughSize, jpeg_file, gfx::Size(256, 256));
}

TEST(JPEGImageDecoderTest, yuv) {
  // This image is 256x256 with YUV 4:2:0
  const char* jpeg_file = "/images/resources/gracehopper.jpg";
  ReadYUV(kLargeEnoughSize, jpeg_file, gfx::Size(256, 256),
          gfx::Size(128, 128));

  // Each plane is in its own scan.
  const char* jpeg_file_non_interleaved =
      "/images/resources/cs-uma-ycbcr-420-non-interleaved.jpg";  // 64x64
  ReadYUV(kLargeEnoughSize, jpeg_file_non_interleaved, gfx::Size(64, 64),
          gfx::Size(32, 32));

  const char* jpeg_file_image_size_not_multiple_of8 =
      "/images/resources/cropped_mandrill.jpg";  // 439x154
  ReadYUV(kLargeEnoughSize, jpeg_file_image_size_not_multiple_of8,
          gfx::Size(439, 154), gfx::Size(220, 77));

  // Make sure we revert to RGBA decoding when we're about to downscale,
  // which can occur on memory-constrained android devices.
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(jpeg_file);
  ASSERT_TRUE(data);

  std::unique_ptr<JPEGImageDecoder> decoder = CreateJPEGDecoder(230 * 230 * 4);
  decoder->SetData(data.get(), true);

  ASSERT_TRUE(decoder->IsSizeAvailable());
  ASSERT_FALSE(decoder->CanDecodeToYUV());
}

// Tests that a progressive image missing an EOI marker causes a YUV decoding
// failure but also results in displayable YUV data.
TEST(JPEGImageDecoderTest, missingEoi) {
  const char* jpeg_file = "/images/resources/missing-eoi.jpg";  // 1599x899
  ReadYUV((1599 * 899 * 4), jpeg_file, gfx::Size(1599, 899),
          gfx::Size(800, 450),
          /*expect_decoding_failure=*/true);
}

TEST(JPEGImageDecoderTest,
     byteByByteBaselineJPEGWithColorProfileAndRestartMarkers) {
  TestByteByByteDecode(&CreateJPEGDecoder,
                       "/images/resources/"
                       "small-square-with-colorspin-profile.jpg",
                       1u, kAnimationNone);
}

TEST(JPEGImageDecoderTest, byteByByteProgressiveJPEG) {
  TestByteByByteDecode(&CreateJPEGDecoder, "/images/resources/bug106024.jpg",
                       1u, kAnimationNone);
}

TEST(JPEGImageDecoderTest, byteByByteRGBJPEGWithAdobeMarkers) {
  TestByteByByteDecode(&CreateJPEGDecoder,
                       "/images/resources/rgb-jpeg-with-adobe-marker-only.jpg",
                       1u, kAnimationNone);
}

// This tests decoding a JPEG with many progressive scans.  Decoding should
// fail, but not hang (crbug.com/642462).
TEST(JPEGImageDecoderTest, manyProgressiveScans) {
  scoped_refptr<SharedBuffer> test_data =
      ReadFileToSharedBuffer(kDecodersTestingDir, "many-progressive-scans.jpg");
  ASSERT_TRUE(test_data.get());

  std::unique_ptr<ImageDecoder> test_decoder = CreateJPEGDecoder();
  test_decoder->SetData(test_data.get(), true);
  EXPECT_EQ(1u, test_decoder->FrameCount());
  ASSERT_TRUE(test_decoder->DecodeFrameBufferAtIndex(0));
  EXPECT_TRUE(test_decoder->Failed());
}

// Decode a JPEG with EXIF data that defines a density corrected size. The EXIF
// data has the initial IFD at the end of the data blob, and out-of-line data
// defined just after the header.
// The order of the EXIF data is:
//   <header> <out-of-line data> <Exif IFD> <0th IFD>
TEST(JPEGImageDecoderTest, exifWithInitialIfdLast) {
  scoped_refptr<SharedBuffer> test_data =
      ReadFileToSharedBuffer(kDecodersTestingDir, "green-exif-ifd-last.jpg");
  ASSERT_TRUE(test_data.get());

  std::unique_ptr<ImageDecoder> test_decoder = CreateJPEGDecoder();
  test_decoder->SetData(test_data.get(), true);
  EXPECT_EQ(1u, test_decoder->FrameCount());
  ASSERT_TRUE(test_decoder->DecodeFrameBufferAtIndex(0));
  EXPECT_EQ(test_decoder->Orientation(), ImageOrientationEnum::kOriginTopRight);
  EXPECT_EQ(test_decoder->DensityCorrectedSize(), gfx::Size(32, 32));
}

TEST(JPEGImageDecoderTest, SupportedSizesSquare) {
  const char* jpeg_file = "/images/resources/gracehopper.jpg";  // 256x256
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(jpeg_file);
  ASSERT_TRUE(data);

  std::unique_ptr<ImageDecoder> decoder =
      CreateJPEGDecoder(std::numeric_limits<int>::max());
  decoder->SetData(data.get(), true);
  // This will decode the size and needs to be called to avoid DCHECKs
  ASSERT_TRUE(decoder->IsSizeAvailable());
  Vector<SkISize> expected_sizes = {
      SkISize::Make(32, 32),   SkISize::Make(64, 64),   SkISize::Make(96, 96),
      SkISize::Make(128, 128), SkISize::Make(160, 160), SkISize::Make(192, 192),
      SkISize::Make(224, 224), SkISize::Make(256, 256)};
  auto sizes = decoder->GetSupportedDecodeSizes();
  ASSERT_EQ(expected_sizes.size(), sizes.size());
  for (size_t i = 0; i < sizes.size(); ++i) {
    EXPECT_TRUE(expected_sizes[i] == sizes[i])
        << "Expected " << expected_sizes[i].width() << "x"
        << expected_sizes[i].height() << ". Got " << sizes[i].width() << "x"
        << sizes[i].height();
  }
}

TEST(JPEGImageDecoderTest, SupportedSizesRectangle) {
  // This 272x200 image uses 4:2:2 sampling format. The MCU is therefore 16x8.
  // The width is a multiple of 16 and the height is a multiple of 8, so it's
  // okay for the decoder to downscale it.
  const char* jpeg_file = "/images/resources/icc-v2-gbr-422-whole-mcus.jpg";

  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(jpeg_file);
  ASSERT_TRUE(data);

  std::unique_ptr<ImageDecoder> decoder =
      CreateJPEGDecoder(std::numeric_limits<int>::max());
  decoder->SetData(data.get(), true);
  // This will decode the size and needs to be called to avoid DCHECKs
  ASSERT_TRUE(decoder->IsSizeAvailable());
  Vector<SkISize> expected_sizes = {
      SkISize::Make(34, 25),   SkISize::Make(68, 50),   SkISize::Make(102, 75),
      SkISize::Make(136, 100), SkISize::Make(170, 125), SkISize::Make(204, 150),
      SkISize::Make(238, 175), SkISize::Make(272, 200)};

  auto sizes = decoder->GetSupportedDecodeSizes();
  ASSERT_EQ(expected_sizes.size(), sizes.size());
  for (size_t i = 0; i < sizes.size(); ++i) {
    EXPECT_TRUE(expected_sizes[i] == sizes[i])
        << "Expected " << expected_sizes[i].width() << "x"
        << expected_sizes[i].height() << ". Got " << sizes[i].width() << "x"
        << sizes[i].height();
  }
}

TEST(JPEGImageDecoderTest,
     SupportedSizesRectangleNotMultipleOfMCUIfMemoryBound) {
  // This 275x207 image uses 4:2:0 sampling format. The MCU is therefore 16x16.
  // Neither the width nor the height is a multiple of the MCU, so downscaling
  // should not be supported. However, we limit the memory so that the decoder
  // is forced to support downscaling.
  const char* jpeg_file = "/images/resources/icc-v2-gbr.jpg";

  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(jpeg_file);
  ASSERT_TRUE(data);

  // Make the memory limit one fewer byte than what is needed in order to force
  // downscaling.
  std::unique_ptr<ImageDecoder> decoder = CreateJPEGDecoder(275 * 207 * 4 - 1);
  decoder->SetData(data.get(), true);
  // This will decode the size and needs to be called to avoid DCHECKs
  ASSERT_TRUE(decoder->IsSizeAvailable());
  Vector<SkISize> expected_sizes = {
      SkISize::Make(35, 26),   SkISize::Make(69, 52),   SkISize::Make(104, 78),
      SkISize::Make(138, 104), SkISize::Make(172, 130), SkISize::Make(207, 156),
      SkISize::Make(241, 182)};

  auto sizes = decoder->GetSupportedDecodeSizes();
  ASSERT_EQ(expected_sizes.size(), sizes.size());
  for (size_t i = 0; i < sizes.size(); ++i) {
    EXPECT_TRUE(expected_sizes[i] == sizes[i])
        << "Expected " << expected_sizes[i].width() << "x"
        << expected_sizes[i].height() << ". Got " << sizes[i].width() << "x"
        << sizes[i].height();
  }
}

TEST(JPEGImageDecoderTest, SupportedSizesRectangleNotMultipleOfMCU) {
  struct {
    const char* jpeg_file;
    SkISize expected_size;
  } recs[] = {
      {// This 264x192 image uses 4:2:0 sampling format. The MCU is therefore
       // 16x16. The height is a multiple of 16, but the width is not a
       // multiple of 16, so it's not okay for the decoder to downscale it.
       "/images/resources/icc-v2-gbr-420-width-not-whole-mcu.jpg",
       SkISize::Make(264, 192)},
      {// This 272x200 image uses 4:2:0 sampling format. The MCU is therefore
       // 16x16. The width is a multiple of 16, but the width is not a multiple
       // of 16, so it's not okay for the decoder to downscale it.
       "/images/resources/icc-v2-gbr-420-height-not-whole-mcu.jpg",
       SkISize::Make(272, 200)}};
  for (const auto& rec : recs) {
    scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(rec.jpeg_file);
    ASSERT_TRUE(data);
    std::unique_ptr<ImageDecoder> decoder =
        CreateJPEGDecoder(std::numeric_limits<int>::max());
    decoder->SetData(data.get(), true);
    // This will decode the size and needs to be called to avoid DCHECKs
    ASSERT_TRUE(decoder->IsSizeAvailable());
    auto sizes = decoder->GetSupportedDecodeSizes();
    ASSERT_EQ(1u, sizes.size());
    EXPECT_EQ(rec.expected_size, sizes[0])
        << "Expected " << rec.expected_size.width() << "x"
        << rec.expected_size.height() << ". Got " << sizes[0].width() << "x"
        << sizes[0].height();
  }
}

TEST(JPEGImageDecoderTest, SupportedSizesTruncatedIfMemoryBound) {
  const char* jpeg_file = "/images/resources/gracehopper.jpg";  // 256x256
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(jpeg_file);
  ASSERT_TRUE(data);

  // Limit the memory so that 128 would be the largest size possible.
  std::unique_ptr<ImageDecoder> decoder = CreateJPEGDecoder(130 * 130 * 4);
  decoder->SetData(data.get(), true);
  // This will decode the size and needs to be called to avoid DCHECKs
  ASSERT_TRUE(decoder->IsSizeAvailable());
  Vector<SkISize> expected_sizes = {
      SkISize::Make(32, 32), SkISize::Make(64, 64), SkISize::Make(96, 96),
      SkISize::Make(128, 128)};
  auto sizes = decoder->GetSupportedDecodeSizes();
  ASSERT_EQ(expected_sizes.size(), sizes.size());
  for (size_t i = 0; i < sizes.size(); ++i) {
    EXPECT_TRUE(expected_sizes[i] == sizes[i])
        << "Expected " << expected_sizes[i].width() << "x"
        << expected_sizes[i].height() << ". Got " << sizes[i].width() << "x"
        << sizes[i].height();
  }
}

TEST(JPEGImageDecoderTest, SupportedScaleNumeratorBound) {
  auto numerator_default = JPEGImageDecoder::DesiredScaleNumerator(10, 9, 8);
  ASSERT_EQ(numerator_default, static_cast<unsigned>(8));

  auto numerator_normal =
      JPEGImageDecoder::DesiredScaleNumerator(1024, 2048, 8);
  ASSERT_EQ(numerator_normal, static_cast<unsigned>(5));

  auto numerator_overflow =
      JPEGImageDecoder::DesiredScaleNumerator(0x4000000, 0x4100000, 8);
  ASSERT_EQ(numerator_overflow, static_cast<unsigned>(7));
}

struct ColorSpaceTestParam {
  std::string file;
  bool expected_success = false;
  bool expect_yuv_decoding = false;
  gfx::Size expected_uv_size;
};

void PrintTo(const ColorSpaceTestParam& param, std::ostream* os) {
  *os << "{\"" << param.file << "\", " << param.expected_success << ","
      << param.expected_uv_size.ToString() << "," << param.expect_yuv_decoding
      << "}";
}

class ColorSpaceTest : public ::testing::TestWithParam<ColorSpaceTestParam> {};

// Tests YUV decoding path with different color encodings (and chroma
// subsamplings if applicable).
TEST_P(ColorSpaceTest, YuvDecode) {
  // Test only successful decoding
  if (!GetParam().expected_success) {
    return;
  }

  if (GetParam().expect_yuv_decoding) {
    const auto jpeg_file = ("/images/resources/" + GetParam().file);
    ReadYUV(kLargeEnoughSize, jpeg_file.c_str(), gfx::Size(64, 64),
            GetParam().expected_uv_size,
            /*expect_decoding_failure=*/false);
  }
}

// Tests RGB decoding path with different color encodings (and chroma
// subsamplings if applicable).
TEST_P(ColorSpaceTest, RgbDecode) {
  // Test only successful decoding
  if (!GetParam().expected_success) {
    return;
  }

  if (!GetParam().expect_yuv_decoding) {
    const auto jpeg_file = ("/images/resources/" + GetParam().file);
    scoped_refptr<SharedBuffer> data =
        ReadFileToSharedBuffer(jpeg_file.c_str());
    ASSERT_TRUE(data);

    std::unique_ptr<ImageDecoder> decoder = CreateJPEGDecoder(kLargeEnoughSize);
    decoder->SetData(data.get(), true);

    gfx::Size size = decoder->DecodedSize();
    EXPECT_EQ(gfx::Size(64, 64), size);
    ASSERT_FALSE(decoder->CanDecodeToYUV());

    const ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(0);
    ASSERT_TRUE(frame);
    EXPECT_EQ(frame->GetStatus(), ImageFrame::kFrameComplete);
    EXPECT_FALSE(decoder->Failed());
    return;
  }
}

const ColorSpaceTest::ParamType kColorSpaceTestParams[] = {
    {"cs-uma-grayscale.jpg", true},
    {"cs-uma-rgb.jpg", true},
    // Each component is in a separate scan. Should not make a difference.
    {"cs-uma-rgb-non-interleaved.jpg", true},
    {"cs-uma-cmyk.jpg", true},
    // 4 components/no markers, so we expect libjpeg_turbo to guess CMYK.
    {"cs-uma-cmyk-no-jfif-or-adobe-markers.jpg", true},
    // 4 components are not legal in JFIF, but we expect libjpeg_turbo to guess
    // CMYK.
    {"cs-uma-cmyk-jfif-marker.jpg", true},
    {"cs-uma-ycck.jpg", true},
    // Contains CMYK data but uses a bad Adobe color transform, so libjpeg_turbo
    // will guess YCCK.
    {"cs-uma-cmyk-unknown-transform.jpg", true},
    {"cs-uma-ycbcr-410.jpg", true, false},
    {"cs-uma-ycbcr-411.jpg", true, false},
    {"cs-uma-ycbcr-420.jpg", true, true, gfx::Size(32, 32)},
    // Each component is in a separate scan. Should not make a difference.
    {"cs-uma-ycbcr-420-non-interleaved.jpg", true, true, gfx::Size(32, 32)},
    // 3 components/both JFIF and Adobe markers, so we expect libjpeg_turbo to
    // guess YCbCr.
    {"cs-uma-ycbcr-420-both-jfif-adobe.jpg", true, true, gfx::Size(32, 32)},
    {"cs-uma-ycbcr-422.jpg", true, true, gfx::Size(32, 64)},
    {"cs-uma-ycbcr-440.jpg", true, false},
    {"cs-uma-ycbcr-444.jpg", true, true, gfx::Size(64, 64)},
    // Contains RGB data but uses a bad Adobe color transform, so libjpeg_turbo
    // will guess YCbCr.
    {"cs-uma-rgb-unknown-transform.jpg", true, true, gfx::Size(64, 64)},
    {"cs-uma-ycbcr-other.jpg", true, false},
    // Contains only 2 components. We expect the decode to fail and not produce
    // any samples.
    {"cs-uma-two-channels-jfif-marker.jpg", false}};

INSTANTIATE_TEST_SUITE_P(JPEGImageDecoderTest,
                         ColorSpaceTest,
                         ::testing::ValuesIn(kColorSpaceTestParams));

TEST(JPEGImageDecoderTest, PartialDataWithoutSize) {
  const char* jpeg_file = "/images/resources/gracehopper.jpg";
  Vector<char> full_data = ReadFile(jpeg_file);

  constexpr size_t kDataLengthWithoutSize = 4;
  ASSERT_LT(kDataLengthWithoutSize, full_data.size());
  scoped_refptr<SharedBuffer> partial_data =
      SharedBuffer::Create(full_data.data(), kDataLengthWithoutSize);

  std::unique_ptr<ImageDecoder> decoder = CreateJPEGDecoder();
  decoder->SetData(partial_data.get(), false);
  EXPECT_FALSE(decoder->IsSizeAvailable());
  EXPECT_FALSE(decoder->Failed());
  decoder->SetData(SharedBuffer::Create(std::move(full_data)), true);
  EXPECT_TRUE(decoder->IsSizeAvailable());
  EXPECT_FALSE(decoder->Failed());
}

TEST(JPEGImageDecoderTest, PartialRgbDecodeBlocksYuvDecoding) {
  const char* jpeg_file = "/images/resources/non-interleaved_progressive.jpg";
  Vector<char> full_data = ReadFile(jpeg_file);

  {
    auto yuv_decoder = CreateJPEGDecoder();
    yuv_decoder->SetData(SharedBuffer::Create(full_data), true);
    EXPECT_TRUE(yuv_decoder->IsSizeAvailable());
    EXPECT_FALSE(yuv_decoder->Failed());
    EXPECT_TRUE(yuv_decoder->CanDecodeToYUV());
  }

  const size_t kJustEnoughDataToStartHeaderParsing = (full_data.size() + 1) / 2;
  auto partial_data = SharedBuffer::Create(full_data.data(),
                                           kJustEnoughDataToStartHeaderParsing);
  ASSERT_TRUE(partial_data);

  auto decoder = CreateJPEGDecoder();
  decoder->SetData(partial_data.get(), false);
  EXPECT_TRUE(decoder->IsSizeAvailable());
  EXPECT_FALSE(decoder->Failed());
  EXPECT_FALSE(decoder->CanDecodeToYUV());

  const ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(0);
  ASSERT_TRUE(frame);
  EXPECT_NE(frame->GetStatus(), ImageFrame::kFrameComplete);
  decoder->SetData(SharedBuffer::Create(std::move(full_data)), true);
  EXPECT_FALSE(decoder->CanDecodeToYUV());
}

TEST(JPEGImageDecoderTest, Gainmap) {
  const char* jpeg_file = "/images/resources/gainmap-trattore0.jpg";
  scoped_refptr<SharedBuffer> full_data = ReadFileToSharedBuffer(jpeg_file);
  ASSERT_TRUE(full_data);

  auto base_decoder = CreateJPEGDecoder();
  base_decoder->SetData(full_data.get(), true);
  ASSERT_TRUE(base_decoder->IsSizeAvailable());
  EXPECT_EQ(gfx::Size(134, 100), base_decoder->DecodedSize());

  SkGainmapInfo gainmap_info;
  scoped_refptr<SegmentReader> gainmap_data;
  ASSERT_TRUE(base_decoder->GetGainmapInfoAndData(gainmap_info, gainmap_data));

  // Ensure that the gainmap information was extracted.
  EXPECT_NEAR(gainmap_info.fDisplayRatioHdr, 2.718f, 1.0e-3f);

  // Ensure that the extracted gainmap image contains an appropriately-sized
  // image.
  auto gainmap_decoder = std::make_unique<JPEGImageDecoder>(
      ImageDecoder::kAlphaNotPremultiplied, ColorBehavior::kTransformToSRGB,
      cc::AuxImage::kGainmap, ImageDecoder::kNoDecodedImageByteLimit);

  gainmap_decoder->SetData(gainmap_data.get(), true);
  ASSERT_TRUE(gainmap_decoder->IsSizeAvailable());
  EXPECT_FALSE(gainmap_decoder->Failed());
  EXPECT_EQ(gfx::Size(33, 25), gainmap_decoder->DecodedSize());
}

TEST(JPEGImageDecoderTest, BppHistogramSmall) {
  constexpr int kImageArea = 500 * 644;  // = 322000
  constexpr int kFileSize = 98527;
  constexpr int kSample =
      (kFileSize * 100 * 8 + kImageArea / 2) / kImageArea;  // = 245
  TestJpegBppHistogram("/images/resources/flowchart.jpg",
                       "Blink.DecodedImage.JpegDensity.Count.0.4MP", kSample);
}

TEST(JPEGImageDecoderTest, BppHistogramSmall16x16) {
  // The centi bpp = 764 * 100 * 8 / (16 * 16) ~= 2388, which is greater than
  // the histogram's max value (1000), so this sample goes into the overflow
  // bucket.
  constexpr int kSample = 1000;
  TestJpegBppHistogram("/images/resources/green.jpg",
                       "Blink.DecodedImage.JpegDensity.Count.0.1MP", kSample);
}

TEST(JPEGImageDecoderTest, BppHistogramSmall900000) {
  constexpr int kImageArea = 1200 * 750;  // = 900000
  constexpr int kFileSize = 13726;
  constexpr int kSample =
      (kFileSize * 100 * 8 + kImageArea / 2) / kImageArea;  // = 12
  TestJpegBppHistogram("/images/resources/peach_900000.jpg",
                       "Blink.DecodedImage.JpegDensity.Count.0.9MP", kSample);
}

TEST(JPEGImageDecoderTest, BppHistogramBig) {
  constexpr int kImageArea = 4032 * 3024;  // = 12192768
  constexpr int kFileSize = 54423;
  constexpr int kSample =
      (kFileSize * 100 * 8 + kImageArea / 2) / kImageArea;  // = 4
  TestJpegBppHistogram("/images/resources/bee.jpg",
                       "Blink.DecodedImage.JpegDensity.Count.13MP", kSample);
}

TEST(JPEGImageDecoderTest, BppHistogramBig13000000) {
  constexpr int kImageArea = 4000 * 3250;  // = 13000000
  constexpr int kFileSize = 49203;
  constexpr int kSample =
      (kFileSize * 100 * 8 + kImageArea / 2) / kImageArea;  // = 3
  TestJpegBppHistogram("/images/resources/peach_13000000.jpg",
                       "Blink.DecodedImage.JpegDensity.Count.13MP", kSample);
}

TEST(JPEGImageDecoderTest, BppHistogramHuge) {
  constexpr int kImageArea = 4624 * 3472;  // = 16054528
  constexpr int kFileSize = 60007;
  constexpr int kSample =
      (kFileSize * 100 * 8 + kImageArea / 2) / kImageArea;  // = 3
  TestJpegBppHistogram("/images/resources/peach.jpg",
                       "Blink.DecodedImage.JpegDensity.Count.14+MP", kSample);
}

TEST(JPEGImageDecoderTest, BppHistogramHuge13000002) {
  constexpr int kImageArea = 3961 * 3282;  // = 13000002
  constexpr int kFileSize = 49325;
  constexpr int kSample =
      (kFileSize * 100 * 8 + kImageArea / 2) / kImageArea;  // = 3
  TestJpegBppHistogram("/images/resources/peach_13000002.jpg",
                       "Blink.DecodedImage.JpegDensity.Count.14+MP", kSample);
}

TEST(JPEGImageDecoderTest, BppHistogramInvalid) {
  base::HistogramTester histogram_tester;
  std::unique_ptr<ImageDecoder> decoder = CreateJPEGDecoder();
  decoder->SetData(
      ReadFileToSharedBuffer("/images/resources/green-truncated.jpg"), true);
  ASSERT_TRUE(decoder->IsSizeAvailable());
  EXPECT_FALSE(decoder->Failed());
  EXPECT_EQ(decoder->FrameCount(), 1u);
  ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(0);
  ASSERT_TRUE(frame);
  EXPECT_NE(ImageFrame::kFrameComplete, frame->GetStatus());
  EXPECT_TRUE(decoder->Failed());
  const base::HistogramTester::CountsMap empty_counts;
  EXPECT_THAT(histogram_tester.GetTotalCountsForPrefix(
                  "Blink.DecodedImage.JpegDensity.Count."),
              testing::ContainerEq(empty_counts));
}

TEST(JPEGImageDecoderTest, BppHistogramGrayscale) {
  TestJpegBppHistogram("/images/resources/cs-uma-grayscale.jpg");
}

}  // namespace blink

"""

```