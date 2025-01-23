Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The request asks for a summary of the functionality of a C++ test file for an AVIF image decoder within the Chromium Blink engine. It also asks about relationships to web technologies (HTML, CSS, JavaScript), logical reasoning with inputs/outputs, common errors, and a summary of the file's purpose.

2. **Identify Key Information:** I scanned the code for keywords and structural elements that reveal its purpose:
    * `_test.cc`: This immediately signals that it's a test file.
    * `CrabbyAVIFImageDecoder`:  This identifies the specific component being tested.
    * `#include "third_party/blink/renderer/platform/image-decoders/avif/crabbyavif_image_decoder.h"`: Confirms the decoder under test.
    * `testing/gtest/include/gtest/gtest.h`:  Indicates the use of Google Test framework.
    * Various `TEST()` macros throughout the code.
    * Helper functions like `CreateAVIFDecoder`, `CreateGainMapAVIFDecoder`, `InspectImage`, `TestInvalidStaticImage`, `ReadYUV`, `TestYUVRed`, etc.
    * Data structures like `StaticColorCheckParam` and `AVIFImageParam` holding test case data.
    * File path strings like `/images/resources/avif/...`.

3. **Infer the Primary Function:** Based on the above, the primary function is clearly to test the `CrabbyAVIFImageDecoder`. This involves:
    * Decoding valid AVIF images and verifying the output (correct pixel colors, dimensions, animation properties, etc.).
    * Handling invalid or malformed AVIF images gracefully.
    * Testing different color profiles, bit depths, alpha options, and other AVIF features.
    * Potentially testing performance or memory usage (though less evident in this snippet).

4. **Analyze Relationships with Web Technologies:**
    * **HTML `<img>` tag:**  The most direct relationship. The AVIF decoder is used when the browser encounters an `<img>` tag with a `.avif` source.
    * **CSS `background-image`:** Similar to `<img>`, CSS can use AVIF images as backgrounds.
    * **JavaScript `Image()` object:**  JavaScript can programmatically load and manipulate images, including AVIF. The decoder is used behind the scenes.
    * **Canvas API:**  While not explicitly mentioned in the code, decoded image data (from AVIF or other formats) can be drawn onto a `<canvas>` element.

5. **Identify Logical Reasoning and Provide Examples:**
    * **Input:** An AVIF image file (e.g., `red-with-alpha-8bpc.avif`).
    * **Processing:** The `CrabbyAVIFImageDecoder` attempts to decode it.
    * **Output (Success):** A `SkBitmap` object containing the decoded pixel data, frame count, repetition count, and other image properties. The tests then assert that specific pixels have the expected colors.
    * **Output (Failure):**  For invalid images, the decoder should set an error flag (`Failed()`) and potentially not be able to determine the size or frame count.
    * **Color Profile Handling:** The tests demonstrate how the decoder handles images with different color profiles, potentially transforming them to sRGB. The `ColorBehavior` enum controls this.

6. **Consider User/Programming Errors:**
    * **Incorrect file path:**  Providing a wrong path to `ReadFileToSharedBuffer` would cause the tests to fail.
    * **Assuming synchronous decoding:**  Image decoding can be asynchronous. Not handling the asynchronous nature correctly could lead to errors in real-world usage. The test file uses `base::WaitableEvent` to handle asynchronicity.
    * **Incorrectly interpreting alpha:**  Forgetting whether an image is pre-multiplied or not can lead to incorrect rendering. The tests cover different `AlphaOption` settings.
    * **Memory management:**  While less apparent in this snippet, failing to properly manage memory allocated during decoding could lead to leaks.

7. **Summarize the Functionality (Part 1):**  Based on the above analysis, I formulated the summary focusing on the core purpose of testing the AVIF decoder, its capabilities, and the types of tests it performs. I made sure to highlight the aspects covered in the first part of the provided code.

8. **Structure the Answer:**  I organized the answer into clear sections (Functionality, Relationship to Web Technologies, Logical Reasoning, Common Errors, Summary) for readability and to directly address the different parts of the request. I used examples where appropriate to illustrate the concepts.

By following this methodical approach, I could break down the code and understand its purpose and implications, even without being an expert in the specific codebase. The key is to look for patterns, keywords, and the overall structure of the code to infer its behavior.
这是一个名为 `crabbyavif_image_decoder_test.cc` 的 C++ 源代码文件，属于 Chromium 浏览器 Blink 渲染引擎中的一部分，专门用于测试 AVIF 图像解码器 (`CrabbyAVIFImageDecoder`) 的功能。

**它的主要功能可以归纳为：**

1. **单元测试 `CrabbyAVIFImageDecoder`:**  该文件包含了一系列的单元测试，用来验证 `CrabbyAVIFImageDecoder` 类在不同场景下的行为是否符合预期。这些测试覆盖了静态图像和动画图像的解码。

2. **测试不同的 AVIF 特性:**  测试用例涵盖了 AVIF 图像的多种特性，例如：
    * **颜色类型:** RGB, RGBA, 灰度 (Mono), 灰度带 Alpha (MonoA)。
    * **位深度:** 8位、10位、12位。
    * **Alpha 预乘:**  测试 Alpha 通道是否预乘。
    * **颜色配置 (Color Behavior):** 测试如何处理图像的颜色配置信息，包括忽略、使用标签信息、转换为 sRGB。
    * **图像方向 (Orientation):** 测试图像的 EXIF 方向信息是否被正确处理。
    * **有损和无损压缩:** 虽然代码中有 `FIXME_DISTINGUISH_LOSSY_OR_LOSSLESS`，但测试用例中实际检查了有损图像的解码。
    * **ICC 颜色配置文件:** 代码中有 `FIXME_SUPPORT_ICC_PROFILE_NO_TRANSFORM` 和 `FIXME_SUPPORT_ICC_PROFILE_TRANSFORM`，暗示了对 ICC 配置文件的测试，但目前可能尚未完全实现。
    * **裁剪区域 (Clean Aperture):** 测试解码带有裁剪信息的图像。
    * **动画图像:** 测试解码动画 AVIF 图像，包括帧数和循环次数。
    * **Gain Map:**  测试解码 Gain Map 类型的 AVIF 图像。
    * **YUV 解码:** 测试直接解码为 YUV 颜色空间的能力。

3. **验证解码结果:**  测试用例会加载不同的 AVIF 图片，然后解码它们，并对解码后的结果进行验证，例如：
    * **特定像素的颜色值:** 验证解码后图像中特定坐标的像素颜色是否与预期一致。
    * **图像的元数据:** 验证解码后的图像尺寸、帧数、循环次数、是否是高位深度图像等元数据是否正确。
    * **解码是否成功:** 验证解码过程是否出错。

**它与 javascript, html, css 的功能有关系，具体体现在：**

该测试文件直接测试的是 Blink 渲染引擎内部的图像解码器。当浏览器在渲染网页时，如果遇到 AVIF 格式的图片（通过 `<img>` 标签、CSS `background-image` 属性等引入），就会调用这个解码器来将图像数据解码成浏览器可以渲染的位图。

**举例说明：**

* **HTML `<img>` 标签:**  当 HTML 中有 `<img src="image.avif">` 时，浏览器会下载 `image.avif` 文件，然后调用 `CrabbyAVIFImageDecoder` 来解码这个文件，最终将解码后的图像显示在页面上。  测试文件中加载的各种 `.avif` 文件，例如 `red-with-alpha-8bpc.avif`，就模拟了这种场景。测试会验证解码后的图像颜色、透明度等是否正确，这直接影响了用户在网页上看到的图像效果。

* **CSS `background-image` 属性:**  如果 CSS 中有 `background-image: url("background.avif");`，解码过程与 `<img>` 标签类似。测试文件中的用例也会覆盖这种场景，确保背景图片能被正确解码和显示。

* **JavaScript `Image()` 对象:**  JavaScript 可以使用 `Image()` 对象来动态加载图片。例如 `const img = new Image(); img.src = 'dynamic.avif';`。  `CrabbyAVIFImageDecoder` 同样会被用于解码通过 JavaScript 加载的 AVIF 图像。

**逻辑推理与假设输入输出：**

假设输入一个名为 `red.avif` 的 AVIF 文件，该文件是一个纯红色 (RGB: 255, 0, 0) 的 8 位深度无 Alpha 通道的图像。

* **假设输入:**  `red.avif` 的二进制数据。
* **处理:** `CrabbyAVIFImageDecoder` 将会解析并解码这些数据。
* **预期输出:**
    * `decoder->IsSizeAvailable()` 应该返回 `true`。
    * `decoder->FrameCount()` 应该返回 `1`。
    * `decoder->DecodeFrameBufferAtIndex(0)` 返回的 `ImageFrame` 对象的 `Bitmap()` 中，所有像素的颜色值都应该接近红色 (SkColorSetARGB(255, 255, 0, 0))。

测试文件中的 `kTestParams` 数组就定义了许多这样的测试用例，指定了输入文件、预期颜色、颜色容差等信息。例如：

```c++
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
```

这个测试用例就验证了 `/images/resources/avif/red-full-range-420-8bpc.avif` 图片解码后，坐标 (0,0), (1,1), (2,2) 的像素颜色是否接近红色。

**用户或编程常见的使用错误：**

虽然这个文件是测试代码，但它可以帮助开发者避免与 AVIF 相关的错误：

* **不支持的 AVIF 特性:**  如果开发者使用了浏览器尚未支持的 AVIF 特性（例如某些特定的编码选项），解码器可能会失败。测试用例帮助识别这些边界情况。
* **错误的颜色配置理解:**  开发者可能不理解 AVIF 图像的颜色配置（例如，是否使用了特定的颜色 Profile），导致在 canvas 上绘制或进行其他图像处理时出现颜色偏差。测试文件中对 `ColorBehavior` 的测试可以帮助验证浏览器对颜色配置的处理是否符合预期。
* **Alpha 通道处理错误:**  开发者可能不清楚图像的 Alpha 通道是否预乘，导致图像透明度显示不正确。测试文件中对 `AlphaOption` 的测试可以帮助确保解码器正确处理 Alpha 通道。
* **内存管理错误 (虽然测试代码中不直接体现):** 在实际的解码器实现中，内存管理非常重要。如果解码器存在内存泄漏，可能会影响浏览器的性能和稳定性。测试虽然不直接测内存泄漏，但可以发现一些导致解码失败的情况，这些失败可能与内存问题有关。

**总结 (Part 1 的功能):**

`crabbyavif_image_decoder_test.cc` 的第一部分主要定义了一些辅助函数、数据结构和初始的静态图像解码测试用例。它构建了测试环境，并开始验证 `CrabbyAVIFImageDecoder` 对于各种静态 AVIF 图像的解码能力，包括不同的颜色类型、位深度、Alpha 选项和颜色配置。  它也初步涉及了颜色配置的处理和图像方向的验证。  此外，它还包含了处理无效 AVIF 图像的测试用例。

### 提示词
```
这是目录为blink/renderer/platform/image-decoders/avif/crabbyavif_image_decoder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
// WARNING: Auto-generated by gen_crabbyavif_wrapper.py.
// Do not modify manually.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/image-decoders/avif/crabbyavif_image_decoder.h"

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
  return std::make_unique<CrabbyAVIFImageDecoder>(
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
      reinterpret_cast<CrabbyAVIFImageDecoder*>(decoder.get())
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
    {"/images
```