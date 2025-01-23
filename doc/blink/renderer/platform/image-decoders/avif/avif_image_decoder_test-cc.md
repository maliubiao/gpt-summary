Response:
My goal is to analyze the given C++ code snippet and summarize its functionality, highlighting connections to web technologies (JavaScript, HTML, CSS), potential logical inferences with input/output examples, common usage errors, and provide a concise overall summary.

**Mental Sandbox Simulation:**

1. **Identify the Core Functionality:** The code is a test suite (`*_test.cc`) for `AVIFImageDecoder`. This means it's designed to verify the correct behavior of the AVIF image decoder in the Chromium Blink engine.

2. **Break Down Key Components:**
    * **`CreateAVIFDecoder*` functions:** These create instances of the `AVIFImageDecoder` with different configurations (alpha handling, bit depth, color behavior, etc.). This suggests testing various decoder options.
    * **`StaticColorCheckParam` and `kTestParams`:**  This struct holds parameters for testing static images, including file paths, expected color information at specific points, and decoder configurations. `kTestParams` is an array of these structs, indicating a series of static image tests.
    * **`InspectImage` function:** This function takes a `StaticColorCheckParam` and an optional bit-depth option. It decodes the AVIF image and compares the actual colors at specified points with the expected colors. This is a crucial function for verifying correct decoding.
    * **`TestInvalidStaticImage` function:** This function tests the decoder's handling of invalid AVIF images, checking for proper error handling during parsing and decoding.
    * **`ReadYUV` and `TestYUVRed` functions:** These functions test the decoder's ability to decode AVIF images directly to YUV color space, potentially for video processing or hardware acceleration. `TestYUVRed` specifically checks if a red image decodes to the expected YUV values.
    * **`DecodeTask` function:** This function seems to simulate decoding in a separate thread, possibly to test threading safety or asynchronous decoding.
    * **`TestAvifBppHistogram` function:** This function likely tests that the decoder correctly records the bits-per-pixel (BPP) of decoded AVIF images for metrics purposes.
    * **`AVIFImageParam` and `kAnimatedTestParams`:**  Similar to the static image parameters, these are for testing animated AVIF images, checking frame counts and loop behavior.

3. **Relate to Web Technologies (HTML, CSS, JavaScript):**
    * **HTML `<img>` tag:**  The AVIF decoder is directly responsible for rendering AVIF images embedded in HTML using the `<img>` tag. The tests ensure that these images are displayed correctly.
    * **CSS `background-image`:**  Similar to the `<img>` tag, the decoder handles AVIF images used as CSS background images.
    * **JavaScript `Image` object and `createImageBitmap`:**  JavaScript can load and manipulate images, including AVIF. The tests verify that the decoder works correctly when images are loaded via JavaScript.
    * **Color profiles and color management:** The code explicitly tests different `ColorBehavior` options and mentions ICC profiles. This directly relates to how browsers handle color accuracy and consistency across different devices, which is crucial for web content.

4. **Identify Logical Inferences and Input/Output:**
    * **Input:**  AVIF image data (byte streams).
    * **Output:** Decoded image data (pixels, frame information, metadata).
    * **Assumptions:** The test images in the `/images/resources/avif/` directory are valid (or intentionally invalid for error testing). The testing framework (gtest) is functioning correctly.

    * **Example (from `kTestParams`):**
        * **Input:** `/images/resources/avif/red-with-alpha-8bpc.avif`
        * **Configuration:** `ColorBehavior::kTag`, `AlphaOption::kNotPremultiplied`
        * **Expected Output:** The pixel at (0, 0) should have an ARGB color of (0, 255, 0, 0) (fully transparent red). The pixel at (1, 1) should be (127, 255, 0, 0) (semi-transparent red), and so on.

5. **Identify Potential Usage Errors:**
    * **Providing invalid AVIF data:** The `TestInvalidStaticImage` function specifically checks for this. A common error would be a corrupted or incomplete AVIF file.
    * **Incorrectly setting alpha options:** If a website uses JavaScript to manipulate image data and incorrectly assumes premultiplied alpha when the image is not, rendering issues can occur. The test suite covers both premultiplied and non-premultiplied alpha.
    * **Assuming specific color behavior:**  Developers might make assumptions about how color profiles are handled. The tests with different `ColorBehavior` options highlight the importance of understanding how the browser interprets color information.

6. **Formulate the Summary:** Combine the identified core functionalities, web technology connections, logical inferences, and potential errors into a concise summary. Emphasize that this is a test file for the AVIF decoder.

By following these steps, I can effectively analyze the code and generate the requested summary, addressing all the specific points raised in the prompt.
好的，这是对提供的C++代码片段的功能归纳：

这个C++代码文件 `avif_image_decoder_test.cc` 是 Chromium Blink 引擎中 AVIF 图像解码器的**测试文件**。它的主要功能是：

1. **测试 AVIF 图像解码器的正确性:**  它通过加载各种不同的 AVIF 图像（包括静态和动态，不同颜色空间、位深度、Alpha 通道、颜色配置等），然后使用 `AVIFImageDecoder` 进行解码，并验证解码结果是否符合预期。

2. **测试静态图像解码:**
   - 针对一系列预定义的 AVIF 静态图像文件，测试解码后的颜色值是否与预期一致。这些测试用例覆盖了不同的颜色类型（RGB, RGBA, Mono, MonoA）、位深度（8, 10, 12）、Alpha 选项（预乘和非预乘）、颜色行为（忽略、使用标签、转换为 sRGB）和图像方向。
   - 还会检查解码后图像的元数据，例如图像是否为高位深度图像。
   - 测试在 `ColorBehavior` 设置为 `kIgnore` 时解码器是否正常工作。
   - 测试解码器是否能正确处理 AVIF 图像中的裁剪信息 (clean aperture)。
   - 测试解码器是否能正确处理 AVIF 图像中的方向信息 (orientation)。

3. **测试 YUV 解码:**
   - 测试 AVIF 解码器是否能够解码到 YUV 色彩空间，这通常用于视频处理或硬件加速。
   - 验证解码后的 YUV 数据的尺寸、步长和像素值是否正确。
   - 检查解码后的元数据是否包含正确的 YUV 子采样信息。

4. **测试动画图像解码 (在后续部分):**  虽然这部分代码没有包含动画相关的测试用例，但从结构和命名（例如 `kAnimatedTestParams`）来看，这个测试文件后续的部分会测试动画 AVIF 图像的解码，包括帧数和循环次数。

5. **测试错误处理:**
   - 测试解码器在遇到无效 AVIF 图像数据时的行为，验证是否能够正确地检测和报告错误，防止崩溃。这包括在解析阶段和解码阶段的错误处理。

6. **测试性能指标 (通过直方图):**
   - 使用 `TestBppHistogram` 函数来测试解码器是否能够正确记录解码图像的每像素比特数 (bits-per-pixel, BPP)，这通常用于性能监控和分析。

**与 JavaScript, HTML, CSS 的关系：**

虽然这个测试文件本身是 C++ 代码，但它直接关系到浏览器如何处理网页上使用的 AVIF 图像：

* **HTML `<img>` 标签和 CSS `background-image`:**  `AVIFImageDecoder` 负责解码通过这些 HTML 和 CSS 属性引入的 AVIF 图像。此测试文件确保解码器能够正确渲染这些图像，包括颜色、透明度和方向。例如，如果测试用例中解码后的颜色不正确，那么在网页上显示的 AVIF 图像也会出现颜色错误。
* **JavaScript `Image` 对象和 `createImageBitmap`:** JavaScript 可以通过这些 API 加载和处理图像，包括 AVIF。`AVIFImageDecoder` 的正确性直接影响到 JavaScript 如何操作这些图像数据。例如，如果 Alpha 通道处理不正确，使用 JavaScript 对图像进行合成或修改时可能会出现意想不到的透明度效果。
* **颜色管理:** 测试用例中对 `ColorBehavior` 的测试涉及到颜色配置文件的处理（虽然目前有一些 `FIXME` 标记），这关系到浏览器如何进行颜色管理，确保在不同设备上显示的颜色一致性。 如果解码器对颜色配置文件的处理有误，那么在支持颜色管理的浏览器中，AVIF 图像的颜色可能会与预期不符。

**逻辑推理举例（假设输入与输出）：**

**假设输入:**  一个名为 `/images/resources/avif/red-with-alpha-8bpc.avif` 的 AVIF 文件，包含一个红色的图像，并且有 Alpha 透明通道。

**预期输出 (基于 `kTestParams` 中的配置):**

* **解码后的图像格式:** RGBA (因为带有 Alpha 通道)
* **像素颜色值（部分）:**
    * `gfx::Point(0, 0)` (左上角):  `SkColorSetARGB(0, 255, 0, 0)` - 完全透明的红色。
    * `gfx::Point(1, 1)`: `SkColorSetARGB(127, 255, 0, 0)` - 半透明的红色。
    * `gfx::Point(2, 2)`: `SkColorSetARGB(255, 255, 0, 0)` - 完全不透明的红色。

**用户或编程常见的使用错误举例：**

* **提供错误的 AVIF 文件:**  用户可能会上传或提供损坏的、不完整的或者格式错误的 AVIF 文件。`TestInvalidStaticImage` 这样的测试用例确保解码器在这种情况下不会崩溃，并能给出错误提示。
* **假设 Alpha 通道总是预乘的或非预乘的:** 开发者在处理图像时可能会错误地假设 AVIF 图像的 Alpha 通道总是以某种方式编码。测试用例覆盖了 `kAlphaPremultiplied` 和 `kAlphaNotPremultiplied` 两种情况，提醒开发者需要根据实际情况处理。
* **忽略颜色管理:** 开发者可能没有考虑到不同颜色空间和颜色配置文件的影响，直接使用解码后的颜色值，导致在不同设备上显示颜色不一致。 测试用例中对 `ColorBehavior` 的测试强调了颜色管理的重要性。

**功能归纳：**

总而言之，`avif_image_decoder_test.cc` 的主要功能是**全面测试 Chromium Blink 引擎中 AVIF 图像解码器的各个方面，包括静态图像和动画图像的解码、不同颜色空间和 Alpha 通道的处理、错误处理以及性能指标的记录，以确保浏览器能够正确可靠地渲染 AVIF 图像。**  它通过大量的测试用例，验证解码器在各种场景下的行为是否符合预期，从而保障用户在浏览包含 AVIF 图像的网页时的体验。

### 提示词
```
这是目录为blink/renderer/platform/image-decoders/avif/avif_image_decoder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/image-decoders/avif/avif_image_decoder.h"

#include <cmath>
#include <memory>
#include <ostream>
#include <utility>
#include <vector>

#include "base/barrier_closure.h"
#include "base/bit_cast.h"
#include "base/functional/bind.h"
#include "base/strings/stringprintf.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/thread_pool.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/image-decoders/image_decoder_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "ui/gfx/color_space.h"
#include "ui/gfx/color_transform.h"

#define FIXME_SUPPORT_ICC_PROFILE_NO_TRANSFORM 0
#define FIXME_SUPPORT_ICC_PROFILE_TRANSFORM 0
#define FIXME_DISTINGUISH_LOSSY_OR_LOSSLESS 0

namespace blink {

namespace {

std::unique_ptr<ImageDecoder> CreateAVIFDecoderWithOptions(
    ImageDecoder::AlphaOption alpha_option,
    ImageDecoder::HighBitDepthDecodingOption high_bit_depth_option,
    ColorBehavior color_behavior,
    cc::AuxImage aux_image,
    ImageDecoder::AnimationOption animation_option) {
  return std::make_unique<AVIFImageDecoder>(
      alpha_option, high_bit_depth_option, color_behavior, aux_image,
      ImageDecoder::kNoDecodedImageByteLimit, animation_option);
}

std::unique_ptr<ImageDecoder> CreateAVIFDecoder() {
  return CreateAVIFDecoderWithOptions(
      ImageDecoder::kAlphaNotPremultiplied, ImageDecoder::kDefaultBitDepth,
      ColorBehavior::kTag, cc::AuxImage::kDefault,
      ImageDecoder::AnimationOption::kUnspecified);
}

std::unique_ptr<ImageDecoder> CreateGainMapAVIFDecoder() {
  return CreateAVIFDecoderWithOptions(
      ImageDecoder::kAlphaNotPremultiplied, ImageDecoder::kDefaultBitDepth,
      ColorBehavior::kTag, cc::AuxImage::kGainmap,
      ImageDecoder::AnimationOption::kUnspecified);
}

struct ExpectedColor {
  gfx::Point point;
  SkColor color;
};

enum class ColorType {
  kRgb,
  kRgbA,
  kMono,
  kMonoA,
};

struct StaticColorCheckParam {
  const char* path;
  int bit_depth;
  ColorType color_type;
  ImageDecoder::CompressionFormat compression_format;
  ImageDecoder::AlphaOption alpha_option;
  ColorBehavior color_behavior;
  ImageOrientationEnum orientation = ImageOrientationEnum::kDefault;
  int color_threshold;
  std::vector<ExpectedColor> colors;
};

std::ostream& operator<<(std::ostream& os, const StaticColorCheckParam& param) {
  const char* color_type;
  switch (param.color_type) {
    case ColorType::kRgb:
      color_type = "kRgb";
      break;
    case ColorType::kRgbA:
      color_type = "kRgbA";
      break;
    case ColorType::kMono:
      color_type = "kMono";
      break;
    case ColorType::kMonoA:
      color_type = "kMonoA";
      break;
  }
  const char* alpha_option =
      (param.alpha_option == ImageDecoder::kAlphaPremultiplied
           ? "kAlphaPremultiplied"
           : "kAlphaNotPremultiplied");
  const char* color_behavior;
  if (param.color_behavior == ColorBehavior::kIgnore) {
    color_behavior = "Ignore";
  } else if (param.color_behavior == ColorBehavior::kTag) {
    color_behavior = "Tag";
  } else {
    DCHECK(param.color_behavior == ColorBehavior::kTransformToSRGB);
    color_behavior = "TransformToSRGB";
  }
  const char* orientation;
  switch (param.orientation) {
    case ImageOrientationEnum::kOriginTopLeft:
      orientation = "kOriginTopLeft";
      break;
    case ImageOrientationEnum::kOriginTopRight:
      orientation = "kOriginTopRight";
      break;
    case ImageOrientationEnum::kOriginBottomRight:
      orientation = "kOriginBottomRight";
      break;
    case ImageOrientationEnum::kOriginBottomLeft:
      orientation = "kOriginBottomLeft";
      break;
    case ImageOrientationEnum::kOriginLeftTop:
      orientation = "kOriginLeftTop";
      break;
    case ImageOrientationEnum::kOriginRightTop:
      orientation = "kOriginRightTop";
      break;
    case ImageOrientationEnum::kOriginRightBottom:
      orientation = "kOriginRightBottom";
      break;
    case ImageOrientationEnum::kOriginLeftBottom:
      orientation = "kOriginLeftBottom";
      break;
  }
  return os << "\nStaticColorCheckParam {\n  path: \"" << param.path
            << "\",\n  bit_depth: " << param.bit_depth
            << ",\n  color_type: " << color_type
            << ",\n  alpha_option: " << alpha_option
            << ",\n  color_behavior: " << color_behavior
            << ",\n  orientation: " << orientation << "\n}";
}

StaticColorCheckParam kTestParams[] = {
    {
        "/images/resources/avif/red-at-12-oclock-with-color-profile-lossy.avif",
        8,
        ColorType::kRgb,
        ImageDecoder::kLossyFormat,
        ImageDecoder::kAlphaNotPremultiplied,  // q=60(lossy)
        ColorBehavior::kTag,
        ImageOrientationEnum::kOriginTopLeft,
        0,
        {},  // we just check that this image is lossy.
    },
    {
        "/images/resources/avif/red-at-12-oclock-with-color-profile-lossy.avif",
        8,
        ColorType::kRgb,
        ImageDecoder::kLossyFormat,
        ImageDecoder::kAlphaNotPremultiplied,  // q=60(lossy)
        ColorBehavior::kIgnore,
        ImageOrientationEnum::kOriginTopLeft,
        0,
        {},  // we just check that the decoder won't crash when
             // ColorBehavior::kIgnore is used.
    },
    {"/images/resources/avif/red-with-alpha-8bpc.avif",
     8,
     ColorType::kRgbA,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kTag,
     ImageOrientationEnum::kOriginTopLeft,
     3,
     {
         {gfx::Point(0, 0), SkColorSetARGB(0, 255, 0, 0)},
         {gfx::Point(1, 1), SkColorSetARGB(127, 255, 0, 0)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 255, 0, 0)},
     }},
    {"/images/resources/avif/red-full-range-420-8bpc.avif",
     8,
     ColorType::kRgb,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kTag,
     ImageOrientationEnum::kOriginTopLeft,
     1,
     {
         {gfx::Point(0, 0), SkColorSetARGB(255, 255, 0, 0)},
         {gfx::Point(1, 1), SkColorSetARGB(255, 255, 0, 0)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 255, 0, 0)},
     }},
    {"/images/resources/avif/red-full-range-unspecified-420-8bpc.avif",
     8,
     ColorType::kRgb,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kTag,
     ImageOrientationEnum::kOriginTopLeft,
     0,
     {
         {gfx::Point(0, 0), SkColorSetARGB(255, 255, 0, 0)},
         {gfx::Point(1, 1), SkColorSetARGB(255, 255, 0, 0)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 255, 0, 0)},
     }},
    {"/images/resources/avif/silver-full-range-srgb-420-8bpc.avif",
     8,
     ColorType::kRgb,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kTag,
     ImageOrientationEnum::kOriginTopLeft,
     0,
     {
         {gfx::Point(0, 0), SkColorSetARGB(255, 192, 192, 192)},
         {gfx::Point(1, 1), SkColorSetARGB(255, 192, 192, 192)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 192, 192, 192)},
     }},
    {"/images/resources/avif/silver-400-matrix-6.avif",
     8,
     ColorType::kRgb,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kTag,
     ImageOrientationEnum::kOriginTopLeft,
     0,
     {
         {gfx::Point(0, 0), SkColorSetARGB(255, 192, 192, 192)},
         {gfx::Point(1, 1), SkColorSetARGB(255, 192, 192, 192)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 192, 192, 192)},
     }},
    {"/images/resources/avif/silver-400-matrix-0.avif",
     8,
     ColorType::kRgb,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kTag,
     ImageOrientationEnum::kOriginTopLeft,
     0,
     {
         {gfx::Point(0, 0), SkColorSetARGB(255, 192, 192, 192)},
         {gfx::Point(1, 1), SkColorSetARGB(255, 192, 192, 192)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 192, 192, 192)},
     }},
    {"/images/resources/avif/alpha-mask-limited-range-8bpc.avif",
     8,
     ColorType::kMono,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kTag,
     ImageOrientationEnum::kOriginTopLeft,
     1,
     {
         {gfx::Point(0, 0), SkColorSetARGB(255, 0, 0, 0)},
         {gfx::Point(1, 1), SkColorSetARGB(255, 128, 128, 128)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 255, 255, 255)},
     }},
    {"/images/resources/avif/alpha-mask-full-range-8bpc.avif",
     8,
     ColorType::kMono,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kTag,
     ImageOrientationEnum::kOriginTopLeft,
     1,
     {
         {gfx::Point(0, 0), SkColorSetARGB(255, 0, 0, 0)},
         {gfx::Point(1, 1), SkColorSetARGB(255, 128, 128, 128)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 255, 255, 255)},
     }},
    {"/images/resources/avif/red-with-alpha-8bpc.avif",
     8,
     ColorType::kRgbA,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaPremultiplied,
     ColorBehavior::kTransformToSRGB,
     ImageOrientationEnum::kOriginTopLeft,
     4,
     {
         {gfx::Point(0, 0), SkColorSetARGB(0, 0, 0, 0)},
         {gfx::Point(1, 1), SkColorSetARGB(127, 255, 0, 0)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 255, 0, 0)},
     }},
#if FIXME_SUPPORT_ICC_PROFILE_NO_TRANSFORM
    {"/images/resources/avif/red-with-profile-8bpc.avif",
     8,
     ColorType::kRgb,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kIgnore,
     ImageOrientationEnum::kOriginTopLeft,
     1,
     {
         {gfx::Point(0, 0), SkColorSetARGB(255, 0, 0, 255)},
         {gfx::Point(1, 1), SkColorSetARGB(255, 0, 0, 255)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 0, 0, 255)},
     }},
#endif
#if FIXME_SUPPORT_ICC_PROFILE_TRANSFORM
    {"/images/resources/avif/red-with-profile-8bpc.avif",
     8,
     ColorType::kRgb,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kTransformToSRGB,
     ImageOrientationEnum::kOriginTopLeft,
     1,
     {
         /*
          * "Color Spin" ICC profile, embedded in this image,
          * changes blue to red.
          */
         {gfx::Point(0, 0), SkColorSetARGB(255, 255, 0, 0)},
         {gfx::Point(1, 1), SkColorSetARGB(255, 255, 0, 0)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 255, 0, 0)},
     }},
#endif
    {"/images/resources/avif/red-with-alpha-10bpc.avif",
     10,
     ColorType::kRgbA,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kTag,
     ImageOrientationEnum::kOriginTopLeft,
     2,
     {
         {gfx::Point(0, 0), SkColorSetARGB(0, 255, 0, 0)},
         {gfx::Point(1, 1), SkColorSetARGB(128, 255, 0, 0)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 255, 0, 0)},
     }},
    {"/images/resources/avif/red-with-alpha-10bpc.avif",
     10,
     ColorType::kRgbA,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaPremultiplied,
     ColorBehavior::kTransformToSRGB,
     ImageOrientationEnum::kOriginTopLeft,
     2,
     {
         {gfx::Point(0, 0), SkColorSetARGB(0, 0, 0, 0)},
         {gfx::Point(1, 1), SkColorSetARGB(128, 255, 0, 0)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 255, 0, 0)},
     }},
    {"/images/resources/avif/red-full-range-420-10bpc.avif",
     10,
     ColorType::kRgb,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kTag,
     ImageOrientationEnum::kOriginTopLeft,
     0,
     {
         {gfx::Point(0, 0), SkColorSetARGB(255, 255, 0, 0)},
         {gfx::Point(1, 1), SkColorSetARGB(255, 255, 0, 0)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 255, 0, 0)},
     }},
    {"/images/resources/avif/alpha-mask-limited-range-10bpc.avif",
     10,
     ColorType::kMono,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kTag,
     ImageOrientationEnum::kOriginTopLeft,
     1,
     {
         {gfx::Point(0, 0), SkColorSetARGB(255, 0, 0, 0)},
         {gfx::Point(1, 1), SkColorSetARGB(255, 128, 128, 128)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 255, 255, 255)},
     }},
    {"/images/resources/avif/alpha-mask-full-range-10bpc.avif",
     10,
     ColorType::kMono,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kTag,
     ImageOrientationEnum::kOriginTopLeft,
     1,
     {
         {gfx::Point(0, 0), SkColorSetARGB(255, 0, 0, 0)},
         {gfx::Point(1, 1), SkColorSetARGB(255, 128, 128, 128)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 255, 255, 255)},
     }},
#if FIXME_SUPPORT_ICC_PROFILE_NO_TRANSFORM
    {"/images/resources/avif/red-with-profile-10bpc.avif",
     10,
     ColorType::kRgb,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kIgnore,
     ImageOrientationEnum::kOriginTopLeft,
     1,
     {
         {gfx::Point(0, 0), SkColorSetARGB(255, 0, 0, 255)},
         {gfx::Point(1, 1), SkColorSetARGB(255, 0, 0, 255)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 0, 0, 255)},
     }},
#endif
#if FIXME_SUPPORT_ICC_PROFILE_TRANSFORM
    {"/images/resources/avif/red-with-profile-10bpc.avif",
     10,
     ColorType::kRgb,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kTransformToSRGB,
     ImageOrientationEnum::kOriginTopLeft,
     1,
     {
         /*
          * "Color Spin" ICC profile, embedded in this image,
          * changes blue to red.
          */
         {gfx::Point(0, 0), SkColorSetARGB(255, 255, 0, 0)},
         {gfx::Point(1, 1), SkColorSetARGB(255, 255, 0, 0)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 255, 0, 0)},
     }},
#endif
    {"/images/resources/avif/red-with-alpha-12bpc.avif",
     12,
     ColorType::kRgbA,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kTag,
     ImageOrientationEnum::kOriginTopLeft,
     2,
     {
         {gfx::Point(0, 0), SkColorSetARGB(0, 255, 0, 0)},
         {gfx::Point(1, 1), SkColorSetARGB(128, 255, 0, 0)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 255, 0, 0)},
     }},
    {"/images/resources/avif/red-with-alpha-12bpc.avif",
     12,
     ColorType::kRgbA,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaPremultiplied,
     ColorBehavior::kTransformToSRGB,
     ImageOrientationEnum::kOriginTopLeft,
     2,
     {
         {gfx::Point(0, 0), SkColorSetARGB(0, 0, 0, 0)},
         {gfx::Point(1, 1), SkColorSetARGB(128, 255, 0, 0)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 255, 0, 0)},
     }},
    {"/images/resources/avif/red-full-range-420-12bpc.avif",
     12,
     ColorType::kRgb,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kTag,
     ImageOrientationEnum::kOriginTopLeft,
     0,
     {
         {gfx::Point(0, 0), SkColorSetARGB(255, 255, 0, 0)},
         {gfx::Point(1, 1), SkColorSetARGB(255, 255, 0, 0)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 255, 0, 0)},
     }},
    {"/images/resources/avif/alpha-mask-limited-range-12bpc.avif",
     12,
     ColorType::kMono,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kTag,
     ImageOrientationEnum::kOriginTopLeft,
     1,
     {
         {gfx::Point(0, 0), SkColorSetARGB(255, 0, 0, 0)},
         {gfx::Point(1, 1), SkColorSetARGB(255, 128, 128, 128)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 255, 255, 255)},
     }},
    {"/images/resources/avif/alpha-mask-full-range-12bpc.avif",
     12,
     ColorType::kMono,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kTag,
     ImageOrientationEnum::kOriginTopLeft,
     1,
     {
         {gfx::Point(0, 0), SkColorSetARGB(255, 0, 0, 0)},
         {gfx::Point(1, 1), SkColorSetARGB(255, 128, 128, 128)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 255, 255, 255)},
     }},
#if FIXME_SUPPORT_ICC_PROFILE_NO_TRANSFORM
    {"/images/resources/avif/red-with-profile-12bpc.avif",
     12,
     ColorType::kRgb,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kIgnore,
     ImageOrientationEnum::kOriginTopLeft,
     1,
     {
         {gfx::Point(0, 0), SkColorSetARGB(255, 0, 0, 255)},
         {gfx::Point(1, 1), SkColorSetARGB(255, 0, 0, 255)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 0, 0, 255)},
     }},
#endif
#if FIXME_SUPPORT_ICC_PROFILE_TRANSFORM
    {"/images/resources/avif/red-with-profile-12bpc.avif",
     12,
     ColorType::kRgb,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kTransformToSRGB,
     ImageOrientationEnum::kOriginTopLeft,
     1,
     {
         /*
          * "Color Spin" ICC profile, embedded in this image,
          * changes blue to red.
          */
         {gfx::Point(0, 0), SkColorSetARGB(255, 255, 0, 0)},
         {gfx::Point(1, 1), SkColorSetARGB(255, 255, 0, 0)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 255, 0, 0)},
     }},
#endif
    {"/images/resources/avif/red-and-purple-crop.avif",
     8,
     ColorType::kRgbA,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kTag,
     ImageOrientationEnum::kOriginTopLeft,
     0,
     {
         // The clean aperture's size is 200x50. The left half is red and the
         // right half is purple. Alpha values in the clean aperture are 255.
         // (Alpha values to the right of the clean aperture are 128.)
         {gfx::Point(0, 0), SkColorSetARGB(255, 255, 0, 0)},       // red
         {gfx::Point(99, 24), SkColorSetARGB(255, 255, 0, 0)},     // red
         {gfx::Point(100, 25), SkColorSetARGB(255, 127, 0, 128)},  // purple
         {gfx::Point(199, 49), SkColorSetARGB(255, 127, 0, 128)},  // purple
     }},
    {"/images/resources/avif/red-full-range-angle-1-420-8bpc.avif",
     8,
     ColorType::kRgb,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kTag,
     ImageOrientationEnum::kOriginLeftBottom,
     0,
     {
         {gfx::Point(0, 0), SkColorSetARGB(255, 255, 0, 0)},
         {gfx::Point(1, 1), SkColorSetARGB(255, 255, 0, 0)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 255, 0, 0)},
     }},
    {"/images/resources/avif/red-full-range-mode-0-420-8bpc.avif",
     8,
     ColorType::kRgb,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kTag,
     ImageOrientationEnum::kOriginBottomLeft,
     0,
     {
         {gfx::Point(0, 0), SkColorSetARGB(255, 255, 0, 0)},
         {gfx::Point(1, 1), SkColorSetARGB(255, 255, 0, 0)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 255, 0, 0)},
     }},
    {"/images/resources/avif/red-full-range-mode-1-420-8bpc.avif",
     8,
     ColorType::kRgb,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kTag,
     ImageOrientationEnum::kOriginTopRight,
     0,
     {
         {gfx::Point(0, 0), SkColorSetARGB(255, 255, 0, 0)},
         {gfx::Point(1, 1), SkColorSetARGB(255, 255, 0, 0)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 255, 0, 0)},
     }},
    {"/images/resources/avif/red-full-range-angle-2-mode-0-420-8bpc.avif",
     8,
     ColorType::kRgb,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kTag,
     ImageOrientationEnum::kOriginTopRight,
     0,
     {
         {gfx::Point(0, 0), SkColorSetARGB(255, 255, 0, 0)},
         {gfx::Point(1, 1), SkColorSetARGB(255, 255, 0, 0)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 255, 0, 0)},
     }},
    {"/images/resources/avif/red-full-range-angle-3-mode-1-420-8bpc.avif",
     8,
     ColorType::kRgb,
     ImageDecoder::kLosslessFormat,
     ImageDecoder::kAlphaNotPremultiplied,
     ColorBehavior::kTag,
     ImageOrientationEnum::kOriginLeftTop,
     0,
     {
         {gfx::Point(0, 0), SkColorSetARGB(255, 255, 0, 0)},
         {gfx::Point(1, 1), SkColorSetARGB(255, 255, 0, 0)},
         {gfx::Point(2, 2), SkColorSetARGB(255, 255, 0, 0)},
     }},
    // TODO(ryoh): Add other color profile images, such as BT2020CL,
    //  SMPTE 274M
    // TODO(ryoh): Add images with different combinations of ColorPrimaries,
    //  TransferFunction and MatrixCoefficients,
    //  such as:
    //   sRGB ColorPrimaries, BT.2020 TransferFunction and
    //   BT.709 MatrixCoefficients
    // TODO(ryoh): Add Mono + Alpha Images.
};

enum class ErrorPhase { kParse, kDecode };

// If 'error_phase' is ErrorPhase::kParse, error is expected during parse
// (SetData() call); else error is expected during decode
// (DecodeFrameBufferAtIndex() call).
void TestInvalidStaticImage(const char* avif_file, ErrorPhase error_phase) {
  std::unique_ptr<ImageDecoder> decoder = CreateAVIFDecoder();

  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(avif_file);
  ASSERT_TRUE(data.get());
  decoder->SetData(std::move(data), true);

  if (error_phase == ErrorPhase::kParse) {
    EXPECT_FALSE(decoder->IsSizeAvailable());
    EXPECT_TRUE(decoder->Failed());
    EXPECT_EQ(0u, decoder->FrameCount());
    EXPECT_FALSE(decoder->DecodeFrameBufferAtIndex(0));
  } else {
    EXPECT_TRUE(decoder->IsSizeAvailable());
    EXPECT_FALSE(decoder->Failed());
    EXPECT_GT(decoder->FrameCount(), 0u);
    ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(0);
    ASSERT_TRUE(frame);
    EXPECT_NE(ImageFrame::kFrameComplete, frame->GetStatus());
    EXPECT_TRUE(decoder->Failed());
  }
}

float HalfFloatToUnorm(uint16_t h) {
  const uint32_t f = ((h & 0x8000) << 16) | (((h & 0x7c00) + 0x1c000) << 13) |
                     ((h & 0x03ff) << 13);
  return base::bit_cast<float>(f);
}

void ReadYUV(const char* file_name,
             const gfx::Size& expected_y_size,
             const gfx::Size& expected_uv_size,
             SkColorType color_type,
             int bit_depth,
             gfx::Point3F* rgb_pixel = nullptr) {
  scoped_refptr<SharedBuffer> data =
      ReadFileToSharedBuffer("web_tests/images/resources/avif/", file_name);
  ASSERT_TRUE(data);

  auto decoder = CreateAVIFDecoder();
  decoder->SetData(std::move(data), true);

  ASSERT_TRUE(decoder->IsDecodedSizeAvailable());
  ASSERT_TRUE(decoder->CanDecodeToYUV());
  EXPECT_NE(decoder->GetYUVSubsampling(), cc::YUVSubsampling::kUnknown);
  EXPECT_NE(decoder->GetYUVColorSpace(),
            SkYUVColorSpace::kIdentity_SkYUVColorSpace);
  EXPECT_EQ(decoder->GetYUVBitDepth(), bit_depth);

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
      std::make_unique<ImagePlanes>(planes, row_bytes, color_type));

  decoder->DecodeToYUV();
  EXPECT_FALSE(decoder->Failed());
  EXPECT_TRUE(decoder->HasDisplayableYUVData());

  auto metadata = decoder->MakeMetadataForDecodeAcceleration();
  EXPECT_EQ(cc::ImageType::kAVIF, metadata.image_type);
  EXPECT_EQ(size, metadata.image_size);
  if (expected_y_size == expected_uv_size) {
    EXPECT_EQ(cc::YUVSubsampling::k444, metadata.yuv_subsampling);
  } else if (expected_y_size.height() == expected_uv_size.height()) {
    EXPECT_EQ(cc::YUVSubsampling::k422, metadata.yuv_subsampling);
  } else {
    EXPECT_EQ(cc::YUVSubsampling::k420, metadata.yuv_subsampling);
  }

  if (!rgb_pixel) {
    return;
  }

  if (bit_depth > 8) {
    rgb_pixel->set_x(reinterpret_cast<uint16_t*>(planes[0])[0]);
    rgb_pixel->set_y(reinterpret_cast<uint16_t*>(planes[1])[0]);
    rgb_pixel->set_z(reinterpret_cast<uint16_t*>(planes[2])[0]);
  } else {
    rgb_pixel->set_x(reinterpret_cast<uint8_t*>(planes[0])[0]);
    rgb_pixel->set_y(reinterpret_cast<uint8_t*>(planes[1])[0]);
    rgb_pixel->set_z(reinterpret_cast<uint8_t*>(planes[2])[0]);
  }

  if (color_type == kGray_8_SkColorType) {
    const float max_channel = (1 << bit_depth) - 1;
    rgb_pixel->set_x(rgb_pixel->x() / max_channel);
    rgb_pixel->set_y(rgb_pixel->y() / max_channel);
    rgb_pixel->set_z(rgb_pixel->z() / max_channel);
  } else if (color_type == kA16_unorm_SkColorType) {
    constexpr float kR16MaxChannel = 65535.0f;
    rgb_pixel->set_x(rgb_pixel->x() / kR16MaxChannel);
    rgb_pixel->set_y(rgb_pixel->y() / kR16MaxChannel);
    rgb_pixel->set_z(rgb_pixel->z() / kR16MaxChannel);
  } else {
    DCHECK_EQ(color_type, kA16_float_SkColorType);
    rgb_pixel->set_x(HalfFloatToUnorm(rgb_pixel->x()));
    rgb_pixel->set_y(HalfFloatToUnorm(rgb_pixel->y()));
    rgb_pixel->set_z(HalfFloatToUnorm(rgb_pixel->z()));
  }

  // Convert our YUV pixel to RGB to avoid an excessive amounts of test
  // expectations. We otherwise need bit_depth * yuv_sampling * color_type.
  gfx::ColorTransform::Options options;
  options.src_bit_depth = bit_depth;
  options.dst_bit_depth = bit_depth;
  auto transform = gfx::ColorTransform::NewColorTransform(
      reinterpret_cast<AVIFImageDecoder*>(decoder.get())
          ->GetColorSpaceForTesting(),
      gfx::ColorSpace(), options);
  transform->Transform(rgb_pixel, 1);
}

void TestYUVRed(const char* file_name,
                const gfx::Size& expected_uv_size,
                SkColorType color_type = kGray_8_SkColorType,
                int bit_depth = 8) {
  SCOPED_TRACE(base::StringPrintf("file_name=%s, color_type=%d", file_name,
                                  int{color_type}));

  constexpr gfx::Size kRedYSize(3, 3);

  gfx::Point3F decoded_pixel;
  ASSERT_NO_FATAL_FAILURE(ReadYUV(file_name, kRedYSize, expected_uv_size,
                                  color_type, bit_depth, &decoded_pixel));

  // Allow the RGB value to be off by one step. 1/max_value is the minimum
  // amount of error possible if error exists for integer sources.
  //
  // For half float values we have additional error from precision limitations,
  // which gets worse at the extents of [-0.5, 1] -- which is the case for our R
  // channel since we're using a pure red source.
  //
  // https://en.wikipedia.org/wiki/Half-precision_floating-point_format#Precision_limitations_on_decimal_values_in_[0,_1]
  const double kMinError = 1.0 / ((1 << bit_depth) - 1);
  const double kError = color_type == kA16_float_SkColorType
                            ? kMinError + std::pow(2, -11)
                            : kMinError;
  EXPECT_NEAR(decoded_pixel.x(), 1, kError);     // R
  EXPECT_NEAR(decoded_pixel.y(), 0, kMinError);  // G
  EXPECT_NEAR(decoded_pixel.z(), 0, kMinError);  // B
}

void DecodeTask(const Vector<char>* data, base::RepeatingClosure* done) {
  std::unique_ptr<ImageDecoder> decoder = CreateAVIFDecoder();

  scoped_refptr<SharedBuffer> data_copy = SharedBuffer::Create();
  data_copy->Append(*data);
  decoder->SetData(std::move(data_copy), true);

  EXPECT_TRUE(decoder->IsSizeAvailable());
  EXPECT_FALSE(decoder->Failed());
  EXPECT_EQ(decoder->FrameCount(), 1u);
  ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(0);
  ASSERT_TRUE(frame);
  EXPECT_EQ(ImageFrame::kFrameComplete, frame->GetStatus());
  EXPECT_FALSE(decoder->Failed());

  done->Run();
}

void InspectImage(
    const StaticColorCheckParam& param,
    ImageDecoder::HighBitDepthDecodingOption high_bit_depth_option) {
  std::unique_ptr<ImageDecoder> decoder = CreateAVIFDecoderWithOptions(
      param.alpha_option, high_bit_depth_option, param.color_behavior,
      cc::AuxImage::kDefault, ImageDecoder::AnimationOption::kUnspecified);
  scoped_refptr<SharedBuffer> data = ReadFileToSharedBuffer(param.path);
  ASSERT_TRUE(data.get());
#if FIXME_DISTINGUISH_LOSSY_OR_LOSSLESS
  EXPECT_EQ(param.compression_format,
            ImageDecoder::GetCompressionFormat(data, "image/avif"));
#endif
  decoder->SetData(std::move(data), true);
  EXPECT_EQ(1u, decoder->FrameCount());
  EXPECT_EQ(kAnimationNone, decoder->RepetitionCount());
  EXPECT_EQ(param.bit_depth > 8, decoder->ImageIsHighBitDepth());
  auto metadata = decoder->MakeMetadataForDecodeAcceleration();
  EXPECT_EQ(cc::ImageType::kAVIF, metadata.image_type);
  // TODO(wtc): Check metadata.yuv_subsampling.
  ImageFrame* frame = decoder->DecodeFrameBufferAtIndex(0);
  ASSERT_TRUE(frame);
  EXPECT_EQ(ImageFrame::kFrameComplete, frame->GetStatus());
  EXPECT_FALSE(decoder->Failed());
  EXPECT_EQ(param.orientation, decoder->Orientation());
  EXPECT_EQ(param.color_type == ColorType::kRgbA ||
                param.color_type == ColorType::kMonoA,
            frame->HasAlpha());
  auto get_color_channel = [](SkColorChannel channel, SkColor color) {
    switch (channel) {
      case SkColorChannel::kR:
        return SkColorGetR(color);
      case SkColorChannel::kG:
        return SkColorGetG(color);
      case SkColorChannel::kB:
        return SkColorGetB(color);
      case SkColorChannel::kA:
        return SkColorGetA(color);
    }
  };
  auto color_difference = [get_color_channel](SkColorChannel channel,
                                              SkColor color1,
                                              SkColor color2) -> int {
    return std::abs(static_cast<int>(get_color_channel(channel, color1)) -
                    static_cast<int>(get_color_channel(channel, color2)));
  };
  for (const auto& expected : param.colors) {
    const SkBitmap& bitmap = frame->Bitmap();
    SkColor frame_color =
        bitmap.getColor(expected.point.x(), expected.point.y());

    EXPECT_LE(color_difference(SkColorChannel::kR, frame_color, expected.color),
              param.color_threshold);
    EXPECT_LE(color_difference(SkColorChannel::kG, frame_color, expected.color),
              param.color_threshold);
    EXPECT_LE(color_difference(SkColorChannel::kB, frame_color, expected.color),
              param.color_threshold);
    // TODO(ryoh): Create alpha_threshold field for alpha channels.
    EXPECT_LE(color_difference(SkColorChannel::kA, frame_color, expected.color),
              param.color_threshold);
    if (param.color_type == ColorType::kMono ||
        param.color_type == ColorType::kMonoA) {
      EXPECT_EQ(SkColorGetR(frame_color), SkColorGetG(frame_color));
      EXPECT_EQ(SkColorGetR(frame_color), SkColorGetB(frame_color));
    }
  }
}

void TestAvifBppHistogram(const char* image_name,
                          const char* histogram_name = nullptr,
                          base::HistogramBase::Sample sample = 0) {
  TestBppHistogram(CreateAVIFDecoder, "Avif", image_name, histogram_name,
                   sample);
}

struct AVIFImageParam {
  const char* path;
  size_t expected_frame_count;
  int expected_repetition_count;
};

constexpr AVIFImageParam kAnimatedTestParams[] = {
    // star-animated-8bpc.avif, star-animated-10bpc.avif, and
    // star-animated-12bpc.avif contain an EditListBox whose `flags` field is
    // equal to 0, meaning the edit list is not repeated. Therefore their
    // `expected_repetition_count` is 0.
    {"/images/resources/avif/star-animated-8bpc.avif", 5u, 0},
    {"/images/resources/avif/star-animated-8bpc-with-alpha.avif", 5u,
     kAnimationLoopInfinite},
    {"/images/resources/avif/star-animated-10bpc.avif", 5u, 0},
    {"/images/resources/avif/star-animated-10bpc-wi
```