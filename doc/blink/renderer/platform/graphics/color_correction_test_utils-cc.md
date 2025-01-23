Response:
Let's break down the thought process for analyzing the given C++ code.

1. **Understand the Goal:** The primary goal is to analyze the provided C++ source code (`color_correction_test_utils.cc`) and explain its functionality, its relationship to web technologies (JavaScript, HTML, CSS), provide examples with hypothetical inputs and outputs, and highlight potential user/programmer errors.

2. **Initial Skim and Keyword Spotting:**  First, I'd quickly skim the code looking for recognizable keywords and patterns. I'd notice:
    * `#include`: Standard C++ includes, hinting at dependencies.
    * `namespace blink`:  Confirms it's part of the Blink rendering engine.
    * `ColorCorrectionTestUtils`: The core class being analyzed.
    * `IsNearlyTheSame`, `ColorSpinSkColorSpace`, `CompareColorCorrectedPixels`, `ConvertPixelsToColorSpaceAndPixelFormatForTest`, `MatchColorSpace`, `MatchSkImages`:  These function names strongly suggest the file is about testing color correction functionality.
    * `skcms`: References to Skia's color management system.
    * `testing/gtest`: Indicates the use of Google Test framework for testing.
    * `PixelFormat`, `PredefinedColorSpace`, `CanvasPixelFormat`: Enums likely related to color representations.
    * Tolerances (e.g., `_8888_color_correction_tolerance`, `floating_point_color_correction_tolerance`):  Reinforces the idea of testing and allowing for slight differences in color values.

3. **Analyze Individual Functions:** Next, I'd examine each function in more detail:

    * **`IsNearlyTheSame`:**  A straightforward comparison function with a tolerance. It's used to account for floating-point inaccuracies or minor differences in color values. It uses `EXPECT_LE` and `EXPECT_GE` which are part of Google Test, confirming its testing purpose.

    * **`ColorSpinSkColorSpace`:**  Contains a large array of `unsigned char`. The function name and the array's initialization with hex values suggest it defines a specific color profile (likely for testing). The `skcms_Parse` call confirms this.

    * **`CompareColorCorrectedPixels`:** This is a crucial function. It takes two sets of pixel data and compares them, considering different pixel formats (`kPixelFormat_8888`, `kPixelFormat_16161616`, `kPixelFormat_hhhh`, `kPixelFormat_ffff`). The logic for `kPixelFormat_8888` with `kUnpremulRoundTripTolerance` is more complex, indicating handling of alpha premultiplication. The use of `std::memcmp` for direct comparison and the `IsNearlyTheSame` function for comparisons with tolerance are key observations.

    * **`ConvertPixelsToColorSpaceAndPixelFormatForTest`:** This function is clearly for converting pixel data between different color spaces and pixel formats. It uses `skcms_Transform` for the core conversion. The logic handles different source and destination formats and color spaces, including the special case for F16 canvas. The use of `CanvasColorParams` further confirms its connection to the rendering pipeline. The handling of ICC profiles is also evident.

    * **`MatchColorSpace`:**  A utility function to compare two `SkColorSpace` objects, using their ICC profiles for a robust comparison.

    * **`MatchSkImages`:** Compares two `SkImage` objects (Skia's image representation). It handles different color types (8-bit and 16-bit float) and allows for a tolerance in the comparison. It also checks image dimensions, alpha types, and color spaces. The use of `readPixels` to access the image data is important.

4. **Identify Core Functionality:** Based on the function analysis, the core functionality of the file is clearly **testing color correction within the Blink rendering engine**. It provides utilities for:
    * Defining test color spaces.
    * Comparing pixel data with a tolerance.
    * Converting pixel data between color spaces and formats.
    * Comparing `SkImage` objects.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):** This is where I'd connect the low-level C++ code to higher-level web concepts:

    * **JavaScript and Canvas:** The `ConvertPixelsToColorSpaceAndPixelFormatForTest` function, especially the handling of `CanvasPixelFormat`, directly relates to the `<canvas>` element in HTML. JavaScript code using the Canvas API can specify different color spaces and pixel formats. This utility helps test that the browser correctly handles these specifications. I'd think about how JavaScript interacts with canvas for image manipulation and how color spaces are relevant there.

    * **CSS Color Properties:** CSS properties like `color`, `background-color`, `image-rendering`, and potentially newer color functions (like `color()` with ICC profiles) are all about specifying colors. The color correction mechanisms tested by this utility are essential for ensuring that these CSS colors are rendered accurately across different devices and color profiles.

    * **HTML Images:**  HTML `<img>` tags can embed images with embedded color profiles. The `MatchSkImages` function likely plays a role in testing that Blink correctly interprets and applies these embedded color profiles when rendering images.

6. **Hypothetical Input and Output Examples:** For each relevant function, I'd create simple examples to illustrate their behavior:

    * **`IsNearlyTheSame`:**  Demonstrate cases where values are within tolerance and outside tolerance.
    * **`CompareColorCorrectedPixels`:** Show how slightly different pixel values are considered "the same" within the defined tolerance. Also, show the impact of `alpha_multiplied` and `premul_unpremul_tolerance`.
    * **`ConvertPixelsToColorSpaceAndPixelFormatForTest`:**  Illustrate converting RGB data from sRGB to a different color space, and changing the pixel format (e.g., from 8-bit to 16-bit).

7. **Identify Potential Errors:** Think about common mistakes developers might make when working with color and graphics:

    * **Incorrect Tolerance:** Setting the tolerance too low might lead to false negatives in tests. Setting it too high might mask real issues.
    * **Mismatched Pixel Formats/Color Spaces:**  Trying to compare or convert data with incompatible formats/spaces without proper conversion can lead to unexpected results.
    * **Forgetting Alpha Premultiplication:**  Not handling alpha correctly (premultiplied vs. unpremultiplied) is a common source of errors in graphics.
    * **Ignoring Color Profiles:**  Assuming all colors are in the sRGB color space can lead to color inaccuracies when dealing with images or displays with different color gamuts.

8. **Structure the Explanation:** Finally, organize the information logically, starting with the overall purpose of the file and then delving into the specifics of each function, its relation to web technologies, examples, and potential errors. Use clear and concise language. The use of headings and bullet points makes the explanation more readable.

By following these steps, I could systematically analyze the C++ code and generate a comprehensive explanation covering the requested aspects. The key is to combine technical understanding of the code with knowledge of web technologies and common programming pitfalls in the domain of color and graphics.
这个C++源代码文件 `color_correction_test_utils.cc` 位于 Chromium Blink 引擎中，其主要功能是**提供一系列用于测试颜色校正功能的实用工具函数**。 这些工具函数旨在简化编写和执行与颜色空间转换、像素格式转换以及图像比较相关的测试。

下面详细列举其功能，并说明与 JavaScript, HTML, CSS 的关系，以及潜在的使用错误和逻辑推理示例：

**主要功能:**

1. **`IsNearlyTheSame(float expected, float actual, float tolerance)`:**
   - **功能:** 比较两个浮点数 `expected` 和 `actual` 是否在给定的 `tolerance` 范围内相等。
   - **目的:**  由于浮点数运算可能存在精度问题，以及颜色校正算法可能引入细微的数值差异，因此不能直接使用 `==` 进行比较。这个函数提供了一种容差比较的方式。

2. **`ColorSpinSkColorSpace()`:**
   - **功能:** 创建并返回一个自定义的 Skia 色彩空间对象 (`sk_sp<SkColorSpace>`)，该色彩空间基于硬编码的 ICC profile 数据 (`colorspin_profile_data`).
   - **目的:** 提供一个用于测试的非标准的色彩空间，方便测试颜色转换功能在不同色彩空间下的行为。

3. **`CompareColorCorrectedPixels(const void* actual_pixels, const void* expected_pixels, size_t num_pixels, PixelFormat pixel_format, PixelsAlphaMultiply alpha_multiplied, UnpremulRoundTripTolerance premul_unpremul_tolerance)`:**
   - **功能:** 比较两块像素数据 `actual_pixels` 和 `expected_pixels` 是否在容差范围内相等。
   - **参数:**
     - `actual_pixels`:  实际的像素数据。
     - `expected_pixels`: 期望的像素数据。
     - `num_pixels`: 像素的数量。
     - `pixel_format`:  像素格式 (例如 `kPixelFormat_8888`, `kPixelFormat_16161616`, `kPixelFormat_hhhh`, `kPixelFormat_ffff`)。
     - `alpha_multiplied`: 指示像素是否已经过 alpha 预乘。
     - `premul_unpremul_tolerance`:  指示是否进行预乘/非预乘的往返测试，并设置相应的容差。
   - **目的:**  这是核心的比较函数，能够根据不同的像素格式和 alpha 处理方式进行像素级别的比较，并使用容差来处理颜色校正带来的细微差异。

4. **`ConvertPixelsToColorSpaceAndPixelFormatForTest(void* src_data, size_t num_elements, PredefinedColorSpace src_color_space, ImageDataStorageFormat src_storage_format, PredefinedColorSpace dst_color_space, CanvasPixelFormat dst_canvas_pixel_format, std::unique_ptr<uint8_t[]>& converted_pixels, PixelFormat pixel_format_for_f16_canvas)`:**
   - **功能:** 将源像素数据从一个色彩空间和像素格式转换为另一个色彩空间和像素格式。
   - **参数:**
     - `src_data`: 源像素数据。
     - `num_elements`: 像素数据的元素数量。
     - `src_color_space`: 源色彩空间 (`PredefinedColorSpace` 枚举值)。
     - `src_storage_format`: 源数据存储格式 (`ImageDataStorageFormat` 枚举值，例如 `kUint8`, `kFloat32`)。
     - `dst_color_space`: 目标色彩空间。
     - `dst_canvas_pixel_format`: 目标 Canvas 像素格式 (`CanvasPixelFormat` 枚举值)。
     - `converted_pixels`:  存储转换后像素数据的 `unique_ptr`。
     - `pixel_format_for_f16_canvas`: 当目标 Canvas 像素格式为 F16 时使用的具体像素格式。
   - **目的:**  用于测试不同色彩空间和像素格式之间的转换功能。它模拟了浏览器在处理图像和 Canvas 内容时可能进行的颜色空间转换。

5. **`MatchColorSpace(sk_sp<SkColorSpace> src_color_space, sk_sp<SkColorSpace> dst_color_space)`:**
   - **功能:** 比较两个 Skia 色彩空间对象是否基本相同。
   - **目的:**  用于验证颜色空间转换或赋值操作是否产生了预期的色彩空间。它通过比较两个色彩空间的 ICC profile 来判断。

6. **`MatchSkImages(sk_sp<SkImage> src_image, sk_sp<SkImage> dst_image, unsigned uint8_tolerance, float f16_tolerance, bool compare_alpha)`:**
   - **功能:** 比较两个 Skia 图像对象是否在容差范围内相同。
   - **参数:**
     - `src_image`: 源图像。
     - `dst_image`: 目标图像。
     - `uint8_tolerance`: 8 位像素比较的容差。
     - `f16_tolerance`: 16 位浮点像素比较的容差。
     - `compare_alpha`: 是否比较 alpha 通道。
   - **目的:**  用于测试图像处理操作，例如解码、颜色校正等，是否产生了预期的图像结果。它会比较图像的尺寸、色彩空间以及像素数据。

**与 JavaScript, HTML, CSS 的关系:**

这些工具函数主要用于测试 Blink 引擎内部的颜色校正功能，而这些功能直接影响着网页在浏览器中的渲染效果。具体关系如下：

* **JavaScript 和 Canvas API:**
    - `ConvertPixelsToColorSpaceAndPixelFormatForTest` 函数模拟了 Canvas API 在处理图像数据时可能发生的颜色空间转换。例如，当 JavaScript 代码使用 `getImageData()` 获取 Canvas 内容，或者使用 `putImageData()` 将图像数据写入 Canvas 时，浏览器可能会进行颜色空间转换。
    - **举例:** 假设一个 JavaScript 程序在 Canvas 上绘制了一个使用 P3 色彩空间的图像，然后使用 `getImageData()` 获取像素数据。Blink 引擎的颜色校正功能需要正确地处理这个 P3 色彩空间。`ConvertPixelsToColorSpaceAndPixelFormatForTest` 可以用于测试从 P3 转换为 sRGB 或其他色彩空间的过程。
    - **假设输入与输出:**  假设输入是 Canvas 上一个红色像素的 P3 色彩空间数据（例如，浮点数表示的 R=1.0, G=0.0, B=0.0），目标色彩空间是 sRGB。`ConvertPixelsToColorSpaceAndPixelFormatForTest` 的输出应该是该红色像素在 sRGB 色彩空间中的对应值（可能略有不同）。

* **HTML 和 `<img>` 标签:**
    - 当浏览器加载带有嵌入 ICC profile 的图像 (例如 JPEG, PNG) 时，Blink 引擎需要使用颜色校正功能将图像的色彩空间转换为显示器的色彩空间，以确保颜色显示的准确性。
    - `MatchSkImages` 可以用于测试图像解码和颜色校正过程。
    - **举例:**  假设一个 HTML 页面包含一个带有 Display P3 色彩配置文件的 PNG 图片。`MatchSkImages` 可以用于比较解码后的 `SkImage` 对象与预期结果，验证颜色校正是否正确应用。

* **CSS 颜色属性:**
    - CSS 颜色属性（如 `color`, `background-color`）可以指定不同的色彩空间（例如 `display-p3`, `rec2020`）。Blink 引擎的颜色校正功能需要能够正确地解释和渲染这些不同色彩空间中的颜色。
    - 虽然这个文件本身不直接操作 CSS，但它测试的底层颜色校正机制是 CSS 颜色渲染的基础。
    - **举例:** 当 CSS 中指定 `color: color(display-p3 1 0 0)` (P3 红色) 时，Blink 需要将其正确转换为显示器可以显示的颜色。相关测试可能会用到 `ConvertPixelsToColorSpaceAndPixelFormatForTest` 来验证色彩空间的转换。

**逻辑推理示例:**

假设我们要测试将一个 sRGB 红色像素转换为 Display P3 色彩空间。

* **假设输入:**
    - `src_data`:  sRGB 红色的像素数据（例如，8 位表示的 R=255, G=0, B=0, A=255）。
    - `src_color_space`: `PredefinedColorSpace::kSRGB`.
    - `dst_color_space`: `PredefinedColorSpace::kDisplayP3`.
    - `src_storage_format`: `ImageDataStorageFormat::kUint8`.
    - `dst_canvas_pixel_format`: `CanvasPixelFormat::kUint8`.
* **执行:** 调用 `ConvertPixelsToColorSpaceAndPixelFormatForTest` 函数进行转换。
* **预期输出:** `converted_pixels` 应该包含 Display P3 色彩空间中对应的红色像素数据。由于 Display P3 的色域比 sRGB 更广，这个红色在 Display P3 中可能会更鲜艳，因此 R 通道的值可能会保持在 255，但实际的色彩值会不同。
* **验证:** 可以使用 `CompareColorCorrectedPixels` 函数将转换后的像素与预期的 Display P3 红色像素数据进行比较，允许一定的容差。

**用户或编程常见的使用错误:**

1. **`IsNearlyTheSame` 中使用过小的 `tolerance`:**  可能导致本应通过的测试失败，因为颜色校正算法可能引入非常小的数值差异。
    - **错误示例:**  设置 `tolerance` 为 0.000001，但实际的颜色校正导致了 0.00001 的差异。
2. **在 `CompareColorCorrectedPixels` 中错误的 `pixel_format` 或 `alpha_multiplied` 设置:**  会导致错误的像素数据解释和比较。
    - **错误示例:**  实际像素是 BGRA 格式，但 `pixel_format` 设置为 RGBA。
    - **错误示例:** 像素数据已经过 alpha 预乘，但 `alpha_multiplied` 设置为 false。
3. **在 `ConvertPixelsToColorSpaceAndPixelFormatForTest` 中使用不匹配的源和目标色彩空间或像素格式:**  可能导致转换失败或产生不期望的结果。
    - **错误示例:**  尝试将 8 位像素数据转换为需要浮点数表示的色彩空间而不进行适当的缩放。
4. **在 `MatchSkImages` 中使用不合适的 `tolerance`:**  类似于 `IsNearlyTheSame`，过小的容差可能导致误判，过大的容差可能掩盖错误。
5. **没有考虑到 Alpha 预乘的影响:** 在比较或转换像素数据时，没有正确处理 alpha 预乘可能会导致错误的结果。`CompareColorCorrectedPixels` 函数的 `premul_unpremul_tolerance` 参数就是为了处理这种情况。
    - **错误示例:**  直接比较预乘和非预乘的像素数据而不进行相应的转换或调整。

总而言之，`color_correction_test_utils.cc` 提供了一套精细的工具，用于确保 Blink 引擎在处理颜色相关的操作时能够保持准确性和一致性。理解这些工具的功能及其与 Web 技术的关系，对于理解浏览器如何渲染网页至关重要。

### 提示词
```
这是目录为blink/renderer/platform/graphics/color_correction_test_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/graphics/color_correction_test_utils.h"

#include "base/containers/heap_array.h"
#include "base/notreached.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/skia/modules/skcms/skcms.h"

namespace blink {

bool ColorCorrectionTestUtils::IsNearlyTheSame(float expected,
                                               float actual,
                                               float tolerance) {
  EXPECT_LE(actual, expected + tolerance);
  EXPECT_GE(actual, expected - tolerance);
  return true;
}

sk_sp<SkColorSpace> ColorCorrectionTestUtils::ColorSpinSkColorSpace() {
  const unsigned char colorspin_profile_data[] = {
      0x00, 0x00, 0x01, 0xea, 0x54, 0x45, 0x53, 0x54, 0x00, 0x00, 0x00, 0x00,
      0x6d, 0x6e, 0x74, 0x72, 0x52, 0x47, 0x42, 0x20, 0x58, 0x59, 0x5a, 0x20,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x61, 0x63, 0x73, 0x70, 0x74, 0x65, 0x73, 0x74, 0x00, 0x00, 0x00, 0x00,
      0x74, 0x65, 0x73, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf6, 0xd6,
      0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xd3, 0x2d, 0x74, 0x65, 0x73, 0x74,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
      0x63, 0x70, 0x72, 0x74, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x0d,
      0x64, 0x65, 0x73, 0x63, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x8c,
      0x77, 0x74, 0x70, 0x74, 0x00, 0x00, 0x01, 0x8c, 0x00, 0x00, 0x00, 0x14,
      0x72, 0x58, 0x59, 0x5a, 0x00, 0x00, 0x01, 0xa0, 0x00, 0x00, 0x00, 0x14,
      0x67, 0x58, 0x59, 0x5a, 0x00, 0x00, 0x01, 0xb4, 0x00, 0x00, 0x00, 0x14,
      0x62, 0x58, 0x59, 0x5a, 0x00, 0x00, 0x01, 0xc8, 0x00, 0x00, 0x00, 0x14,
      0x72, 0x54, 0x52, 0x43, 0x00, 0x00, 0x01, 0xdc, 0x00, 0x00, 0x00, 0x0e,
      0x67, 0x54, 0x52, 0x43, 0x00, 0x00, 0x01, 0xdc, 0x00, 0x00, 0x00, 0x0e,
      0x62, 0x54, 0x52, 0x43, 0x00, 0x00, 0x01, 0xdc, 0x00, 0x00, 0x00, 0x0e,
      0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x64, 0x65, 0x73, 0x63, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x10, 0x77, 0x68, 0x61, 0x63, 0x6b, 0x65, 0x64, 0x2e,
      0x69, 0x63, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x58, 0x59, 0x5a, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf3, 0x52,
      0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x16, 0xcc, 0x58, 0x59, 0x5a, 0x20,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x8d, 0x00, 0x00, 0xa0, 0x2c,
      0x00, 0x00, 0x0f, 0x95, 0x58, 0x59, 0x5a, 0x20, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x26, 0x31, 0x00, 0x00, 0x10, 0x2f, 0x00, 0x00, 0xbe, 0x9b,
      0x58, 0x59, 0x5a, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9c, 0x18,
      0x00, 0x00, 0x4f, 0xa5, 0x00, 0x00, 0x04, 0xfc, 0x63, 0x75, 0x72, 0x76,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x33};
  skcms_ICCProfile colorspin_profile;
  skcms_Parse(colorspin_profile_data, sizeof(colorspin_profile_data),
              &colorspin_profile);
  return SkColorSpace::Make(colorspin_profile);
}

void ColorCorrectionTestUtils::CompareColorCorrectedPixels(
    const void* actual_pixels,
    const void* expected_pixels,
    size_t num_pixels,
    PixelFormat pixel_format,
    PixelsAlphaMultiply alpha_multiplied,
    UnpremulRoundTripTolerance premul_unpremul_tolerance) {
  bool test_passed = true;
  int _8888_color_correction_tolerance = 3;
  int _16161616_color_correction_tolerance = 255;
  float floating_point_color_correction_tolerance = 0.01;
  if (premul_unpremul_tolerance == kNoUnpremulRoundTripTolerance)
    floating_point_color_correction_tolerance = 0;

  switch (pixel_format) {
    case kPixelFormat_8888: {
      if (premul_unpremul_tolerance == kUnpremulRoundTripTolerance) {
        // Premul->unpremul->premul round trip does not introduce any error when
        // rounding intermediate results. However, we still might see some error
        // introduced in consecutive color correction operations (error <= 3).
        // For unpremul->premul->unpremul round trip, we do premul and compare
        // the result.
        const uint8_t* actual_pixels_u8 =
            static_cast<const uint8_t*>(actual_pixels);
        const uint8_t* expected_pixels_u8 =
            static_cast<const uint8_t*>(expected_pixels);
        for (size_t i = 0; test_passed && i < num_pixels; i++) {
          test_passed &=
              (actual_pixels_u8[i * 4 + 3] == expected_pixels_u8[i * 4 + 3]);
          int alpha_multiplier =
              alpha_multiplied ? 1 : expected_pixels_u8[i * 4 + 3];
          for (size_t j = 0; j < 3; j++) {
            test_passed &= IsNearlyTheSame(
                actual_pixels_u8[i * 4 + j] * alpha_multiplier,
                expected_pixels_u8[i * 4 + j] * alpha_multiplier,
                _8888_color_correction_tolerance);
          }
        }
      } else {
        EXPECT_EQ(std::memcmp(actual_pixels, expected_pixels, num_pixels * 4),
                  0);
      }
      break;
    }

    case kPixelFormat_16161616: {
      const uint16_t* actual_pixels_u16 =
          static_cast<const uint16_t*>(actual_pixels);
      const uint16_t* expected_pixels_u16 =
          static_cast<const uint16_t*>(expected_pixels);
      for (size_t i = 0; test_passed && i < num_pixels * 4; i++) {
        test_passed &=
            IsNearlyTheSame(actual_pixels_u16[i], expected_pixels_u16[i],
                            _16161616_color_correction_tolerance);
      }
      break;
    }

    case kPixelFormat_hhhh: {
      auto actual_pixels_f32 = base::HeapArray<float>::Uninit(num_pixels * 4);
      auto expected_pixels_f32 = base::HeapArray<float>::Uninit(num_pixels * 4);
      EXPECT_TRUE(
          skcms_Transform(actual_pixels, skcms_PixelFormat_RGBA_hhhh,
                          skcms_AlphaFormat_Unpremul, nullptr,
                          actual_pixels_f32.data(), skcms_PixelFormat_BGRA_ffff,
                          skcms_AlphaFormat_Unpremul, nullptr, num_pixels));
      EXPECT_TRUE(
          skcms_Transform(expected_pixels, skcms_PixelFormat_RGBA_hhhh,
                          skcms_AlphaFormat_Unpremul, nullptr,
                          expected_pixels_f32.data(), skcms_PixelFormat_BGRA_ffff,
                          skcms_AlphaFormat_Unpremul, nullptr, num_pixels));

      for (size_t i = 0; test_passed && i < num_pixels * 4; i++) {
        test_passed &=
            IsNearlyTheSame(actual_pixels_f32[i], expected_pixels_f32[i],
                            floating_point_color_correction_tolerance);
      }
      break;
    }

    case kPixelFormat_ffff: {
      const float* actual_pixels_f32 = static_cast<const float*>(actual_pixels);
      const float* expected_pixels_f32 =
          static_cast<const float*>(expected_pixels);
      for (size_t i = 0; test_passed && i < num_pixels * 4; i++) {
        test_passed &=
            IsNearlyTheSame(actual_pixels_f32[i], expected_pixels_f32[i],
                            floating_point_color_correction_tolerance);
      }
      break;
    }

    default:
      NOTREACHED();
  }
  EXPECT_EQ(test_passed, true);
}

bool ColorCorrectionTestUtils::ConvertPixelsToColorSpaceAndPixelFormatForTest(
    void* src_data,
    size_t num_elements,
    PredefinedColorSpace src_color_space,
    ImageDataStorageFormat src_storage_format,
    PredefinedColorSpace dst_color_space,
    CanvasPixelFormat dst_canvas_pixel_format,
    std::unique_ptr<uint8_t[]>& converted_pixels,
    PixelFormat pixel_format_for_f16_canvas) {
  skcms_PixelFormat src_pixel_format = skcms_PixelFormat_RGBA_8888;
  if (src_storage_format == ImageDataStorageFormat::kUint16) {
    src_pixel_format = skcms_PixelFormat_RGBA_16161616LE;
  } else if (src_storage_format == ImageDataStorageFormat::kFloat32) {
    src_pixel_format = skcms_PixelFormat_RGBA_ffff;
  }

  skcms_PixelFormat dst_pixel_format = skcms_PixelFormat_RGBA_8888;
  if (dst_canvas_pixel_format == CanvasPixelFormat::kF16) {
    dst_pixel_format = (pixel_format_for_f16_canvas == kPixelFormat_hhhh)
                           ? skcms_PixelFormat_RGBA_hhhh
                           : skcms_PixelFormat_RGBA_ffff;
  }

  sk_sp<SkColorSpace> src_sk_color_space = nullptr;
  src_sk_color_space =
      CanvasColorParams(src_color_space,
                        (src_storage_format == ImageDataStorageFormat::kUint8)
                            ? CanvasPixelFormat::kUint8
                            : CanvasPixelFormat::kF16,
                        kNonOpaque)
          .GetSkColorSpace();
  if (!src_sk_color_space.get())
    src_sk_color_space = SkColorSpace::MakeSRGB();

  sk_sp<SkColorSpace> dst_sk_color_space =
      CanvasColorParams(dst_color_space, dst_canvas_pixel_format, kNonOpaque)
          .GetSkColorSpace();
  if (!dst_sk_color_space.get())
    dst_sk_color_space = SkColorSpace::MakeSRGB();

  skcms_ICCProfile* src_profile_ptr = nullptr;
  skcms_ICCProfile* dst_profile_ptr = nullptr;
  skcms_ICCProfile src_profile, dst_profile;
  src_sk_color_space->toProfile(&src_profile);
  dst_sk_color_space->toProfile(&dst_profile);
  // If the profiles are similar, we better leave them as nullptr, since
  // skcms_Transform() only checks for profile pointer equality for the fast
  // path.
  if (!skcms_ApproximatelyEqualProfiles(&src_profile, &dst_profile)) {
    src_profile_ptr = &src_profile;
    dst_profile_ptr = &dst_profile;
  }

  skcms_AlphaFormat alpha_format = skcms_AlphaFormat_Unpremul;
  bool conversion_result =
      skcms_Transform(src_data, src_pixel_format, alpha_format, src_profile_ptr,
                      converted_pixels.get(), dst_pixel_format, alpha_format,
                      dst_profile_ptr, num_elements / 4);

  return conversion_result;
}

bool ColorCorrectionTestUtils::MatchColorSpace(
    sk_sp<SkColorSpace> src_color_space,
    sk_sp<SkColorSpace> dst_color_space) {
  if ((!src_color_space && dst_color_space) ||
      (src_color_space && !dst_color_space))
    return false;
  if (!src_color_space && !dst_color_space)
    return true;
  skcms_ICCProfile src_profile, dst_profile;
  src_color_space->toProfile(&src_profile);
  dst_color_space->toProfile(&dst_profile);
  return skcms_ApproximatelyEqualProfiles(&src_profile, &dst_profile);
}

bool ColorCorrectionTestUtils::MatchSkImages(sk_sp<SkImage> src_image,
                                             sk_sp<SkImage> dst_image,
                                             unsigned uint8_tolerance,
                                             float f16_tolerance,
                                             bool compare_alpha) {
  if ((!src_image && dst_image) || (src_image && !dst_image))
    return false;
  if (!src_image)
    return true;
  if ((src_image->width() != dst_image->width()) ||
      (src_image->height() != dst_image->height())) {
    return false;
  }

  if (compare_alpha && src_image->alphaType() != dst_image->alphaType())
    return false;
  // Color type is not checked since the decoded image does not have a specific
  // color type, unless it is drawn onto a surface or readPixels() is called.
  // Only compare color spaces if both are non-null
  if (src_image->refColorSpace() && dst_image->refColorSpace()) {
    if (!MatchColorSpace(src_image->refColorSpace(),
                         dst_image->refColorSpace())) {
      return false;
    }
  }

  bool test_passed = true;
  int num_pixels = src_image->width() * src_image->height();
  int num_components = compare_alpha ? 4 : 3;

  SkImageInfo src_info = SkImageInfo::Make(
      src_image->width(), src_image->height(), kN32_SkColorType,
      src_image->alphaType(), src_image->refColorSpace());

  SkImageInfo dst_info = SkImageInfo::Make(
      dst_image->width(), dst_image->height(), kN32_SkColorType,
      src_image->alphaType(), dst_image->refColorSpace());

  if (src_image->colorType() != kRGBA_F16_SkColorType) {
    auto src_pixels = base::HeapArray<uint8_t>::Uninit(num_pixels * 4);
    auto dst_pixels = base::HeapArray<uint8_t>::Uninit(num_pixels * 4);

    src_image->readPixels(src_info, src_pixels.data(), src_info.minRowBytes(),
                          0, 0);
    dst_image->readPixels(dst_info, dst_pixels.data(), dst_info.minRowBytes(),
                          0, 0);

    for (size_t i = 0; test_passed && i < src_pixels.size(); i++) {
      for (int j = 0; j < num_components; j++) {
        test_passed &= IsNearlyTheSame(src_pixels[i * 4 + j],
                                       dst_pixels[i * 4 + j], uint8_tolerance);
      }
    }
    return test_passed;
  }

  auto src_pixels = base::HeapArray<float>::Uninit(num_pixels * 4);
  auto dst_pixels = base::HeapArray<float>::Uninit(num_pixels * 4);

  src_info = src_info.makeColorType(kRGBA_F32_SkColorType);
  dst_info = dst_info.makeColorType(kRGBA_F32_SkColorType);

  src_image->readPixels(src_info, src_pixels.data(), src_info.minRowBytes(), 0,
                        0);
  dst_image->readPixels(dst_info, dst_pixels.data(), dst_info.minRowBytes(), 0,
                        0);

  for (size_t i = 0; test_passed && i < src_pixels.size(); i++) {
    for (int j = 0; j < num_components; j++) {
      test_passed &= IsNearlyTheSame(src_pixels[i * 4 + j],
                                     dst_pixels[i * 4 + j], f16_tolerance);
    }
  }
  return test_passed;
}

}  // namespace blink
```