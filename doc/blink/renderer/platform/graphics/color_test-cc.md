Response:
Let's break down the thought process for analyzing the `color_test.cc` file.

1. **Understand the Goal:** The primary goal is to understand the *functionality* of the `color_test.cc` file within the Chromium Blink engine. This means figuring out *what* it tests and *how* it tests it. The prompt also asks to relate it to web technologies (JavaScript, HTML, CSS), explain logic, and identify common errors.

2. **Initial Scan and Keywords:** Quickly read through the code, looking for key terms and patterns. Notice:
    * `#include`: This tells us about dependencies. `color.h`, `gtest/gtest.h`, and `wtf_string.h` are important.
    * `namespace blink`: This confirms it's part of the Blink rendering engine.
    * `TEST(...)`: This is a clear indicator of unit tests using the Google Test framework. The first argument to `TEST` is the test suite name, and the second is the test name.
    * `EXPECT_...`: These are assertion macros from Google Test. They are the core of the tests, checking if expected conditions are met.
    * `Color`:  This is a central class being tested. Look for how `Color` objects are created and manipulated.
    * `Color::ColorSpace`: This suggests the code is testing different color models (sRGB, Lab, HSL, etc.).
    * `FromColorSpace`, `FromColorMix`, `InterpolateColors`, `ConvertToColorSpace`, `ExportAsXYZD50Floats`, `PremultiplyColor`, `UnpremultiplyColor`: These are methods of the `Color` class that are being tested.
    * `ColorMixTest`, `ColorTest`, `ColorsTest`, `HueTest`, `ColorFunctionValues`, `FloatValues`: These are helper structs to organize test data.

3. **Identify Core Functionality (Based on Tests):**  Go through each `TEST` block and infer what it's testing:
    * `ColorMixSameColorSpace`: Tests mixing two colors within the same color space. Pay attention to the parameters: `mix_space`, `hue_method`, `color_left`, `color_right`, `percentage_right`, `alpha_multiplier`. This clearly relates to the CSS `color-mix()` function.
    * `ColorMixNone`: Tests a specific case of `color-mix()` where some color components are "none".
    * `ColorInterpolation`: Tests the general concept of interpolating between two colors in a specified color space. This relates to CSS animations and transitions involving color changes.
    * `HueInterpolation`: Focuses specifically on how hue values are interpolated, with different methods ("shorter", "longer", etc.). This is important for smooth color transitions.
    * `toSkColor4fValidation`:  Tests the conversion of the `Color` object to Skia's `SkColor4f` format. This is crucial for rendering. It also indirectly tests conversions *between* color spaces by converting to a target space and back.
    * `ExportAsXYZD50Floats`: Tests the ability to represent a color in the CIE XYZ D50 color space as individual float values. This is an important intermediate format for color transformations.
    * `Premultiply`: Tests the premultiplication of color components by the alpha value. This is an optimization technique used in graphics rendering.
    * `Unpremultiply`: Tests the reverse operation of unpremultiplying color components.

4. **Relate to Web Technologies (JavaScript, HTML, CSS):**  Think about how the tested color functionalities map to web development:
    * **CSS:** The most direct connection. `color-mix()`, color interpolation in animations/transitions, different color spaces (`srgb`, `lab`, `lch`, etc.), and alpha transparency are all CSS features. Provide examples of CSS code that would utilize these concepts.
    * **JavaScript:**  JavaScript can manipulate styles, including colors. The tested color functionalities are the underlying mechanisms that JavaScript interacts with when setting color values. Provide examples using the CSSOM.
    * **HTML:** While HTML itself doesn't directly deal with color *manipulation*, it's where elements that *get* styled reside. Mention how HTML elements are the targets of CSS color styling.

5. **Explain Logic and Provide Examples:** For tests involving calculations (like `ColorMix` and `HueInterpolation`), explain the basic logic. Provide simplified input and expected output examples. This demonstrates understanding of *what* the code is doing.

6. **Identify Potential User/Programming Errors:** Think about common mistakes developers might make when working with colors:
    * Incorrect color space specification.
    * Mixing colors in unintended color spaces.
    * Incorrect percentage values in `color-mix()`.
    * Forgetting about alpha and premultiplication.
    * Issues with hue interpolation (e.g., unexpected color shifts).

7. **Structure and Summarize:** Organize the findings into clear sections (Functionality, Relationship to Web Technologies, Logic and Examples, Common Errors). Provide a concise summary of the file's purpose. Emphasize that it's a *testing* file.

8. **Review and Refine:** Read through the analysis to ensure clarity, accuracy, and completeness. Check if all parts of the prompt have been addressed. For instance, make sure the examples are illustrative and easy to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus too much on the C++ implementation details.
* **Correction:** Shift focus to the *functional* aspects being tested and their relevance to web technologies.
* **Initial thought:**  Only provide general statements about CSS.
* **Correction:** Provide specific CSS examples using `color-mix()`, transitions, and different color space functions.
* **Initial thought:**  Overlook the "none" keyword in color functions.
* **Correction:**  Recognize the `ColorMixNone` test and explain its significance.
* **Initial thought:**  Not explicitly state that this is a *testing* file.
* **Correction:**  Clearly state in the summary that the file's purpose is to test the `Color` class.

By following this structured thought process, moving from a broad overview to specific details, and constantly relating the code back to its purpose within the web development context, it's possible to generate a comprehensive and accurate analysis of the `color_test.cc` file.好的，让我们来分析一下 `blink/renderer/platform/graphics/color_test.cc` 这个文件。

**文件功能归纳：**

`color_test.cc` 文件是 Chromium Blink 引擎中用于测试 `blink::Color` 类功能的单元测试文件。它使用 Google Test 框架来验证 `Color` 类的各种方法和操作是否按预期工作。

**具体功能点：**

1. **颜色混合 (`ColorMix`) 测试:**
   - 测试在同一颜色空间下混合两个颜色的功能。
   - 验证 `Color::FromColorMix` 方法的正确性，包括不同百分比、alpha 透明度和 hue 插值方法（虽然本部分代码中 `hue_method` 大多为 `std::nullopt`，暗示后续部分会涉及）。
   - 涵盖了 sRGB 颜色空间的混合，以及不同颜色空间到 sRGB 的混合结果验证。
   - 测试了带有 "none" 值的颜色混合情况。

2. **颜色插值 (`ColorInterpolation`) 测试:**
   - 测试在不同颜色空间之间插值两个颜色的功能。
   - 验证 `Color::InterpolateColors` 方法的正确性，包括不同的颜色空间（sRGB, HSL, HWB, Lab, Lch 等）、插值百分比和 hue 插值方法。
   - 这些测试用例很多来源于 CSS Color 4 规范。

3. **Hue 插值 (`HueInterpolation`) 测试:**
   - 专门测试色相（hue）值的插值计算。
   - 验证 `Color::HueInterpolation` 函数在不同插值方法（shorter, longer, increasing, decreasing）下的行为。

4. **转换为 SkColor4f (`toSkColor4fValidation`) 的验证:**
   - 间接测试颜色空间转换的正确性。
   - 它将各种颜色空间的 `Color` 对象转换为 Skia 的 `SkColor4f` 格式，然后再将转换后的颜色对象转换回 `SkColor4f`，并与原始直接转换的 `SkColor4f` 值进行比较。
   - 这里依赖于 `color_conversions_test.cc` 中对 `toSkColor4f` 的直接验证。

5. **导出为 XYZD50 浮点数 (`ExportAsXYZD50Floats`) 测试:**
   - 测试将 `Color` 对象导出为 CIE XYZ D50 颜色空间的浮点数值的能力。
   - 验证了不同颜色空间转换到 XYZD50 再导出的精度。

6. **预乘 (`Premultiply`) 测试:**
   - 测试颜色分量是否能正确地与 alpha 值进行预乘。
   - 涵盖了矩形颜色空间和极坐标颜色空间的预乘，以及带有 "none" 值的颜色分量的处理。

**与 JavaScript, HTML, CSS 的关系：**

这个测试文件直接关系到 CSS 的颜色功能，因为它测试了 Blink 引擎中处理颜色和颜色空间的核心逻辑。这些功能最终会暴露给 Web 开发者，让他们可以通过 CSS 来控制网页元素的颜色。

* **CSS:**
    * **`color-mix()` 函数:** `ColorMix` 测试直接对应于 CSS 的 `color-mix()` 函数，该函数允许混合两种颜色。例如：
      ```css
      .element {
        background-color: color-mix(in srgb, red, blue 50%); /* 对应 ColorMixSameColorSpace 中的测试 */
      }
      ```
    * **颜色插值 (动画和过渡):** `ColorInterpolation` 测试与 CSS 动画和过渡中颜色的平滑变化有关。例如：
      ```css
      .element {
        background-color: red;
        transition: background-color 1s;
      }
      .element:hover {
        background-color: blue; /* 浏览器内部会进行颜色插值 */
      }
      ```
    * **不同的颜色空间:** 测试中涉及的 sRGB, HSL, HWB, Lab, Lch, Display P3, Rec2020 等都是 CSS Color Module Level 4 中定义的颜色空间。例如：
      ```css
      .element {
        background-color: lch(50% 100 40);
      }
      ```
    * **`none` 关键字:** `ColorMixNone` 测试与 CSS 颜色函数中可以使用 `none` 关键字来表示缺失的颜色分量有关。例如：
      ```css
      .element {
        background-color: color(display-p3 none 0.5 1);
      }
      ```
    * **Alpha 透明度:** 预乘和反预乘测试与 CSS 中使用 alpha 值控制透明度有关。当浏览器渲染带有透明度的元素时，会涉及到颜色的预乘操作。

* **JavaScript:**
    * JavaScript 可以通过 DOM API 来获取和设置元素的样式，包括颜色。例如：
      ```javascript
      const element = document.querySelector('.element');
      element.style.backgroundColor = 'rgb(255, 0, 0)'; // 设置 sRGB 颜色
      const bgColor = getComputedStyle(element).backgroundColor; // 获取计算后的颜色值
      ```
    * 当 JavaScript 操作颜色值时，Blink 引擎内部会使用 `blink::Color` 类进行处理，因此这里的测试也间接关系到 JavaScript 的颜色操作。

* **HTML:**
    * HTML 定义了网页的结构，而 CSS 负责样式。HTML 元素是 CSS 颜色属性的应用对象。例如：
      ```html
      <div class="element" style="background-color: red;"></div>
      ```

**逻辑推理、假设输入与输出：**

以 `TEST(BlinkColor, ColorMixSameColorSpace)` 中的第一个测试用例为例：

* **假设输入:**
    * `mix_space`: `Color::ColorSpace::kSRGB`
    * `color_left`: sRGB(1.0f, 0.0f, 0.0f, 1.0f)  (红色)
    * `color_right`: sRGB(0.0f, 1.0f, 0.0f, 1.0f) (绿色)
    * `percentage_right`: 0.5f
    * `alpha_multiplier`: 1.0f
* **逻辑推理:** 将红色和绿色以 50% 的比例在 sRGB 空间混合，alpha 乘数为 1，结果应该是红绿各一半的颜色，即黄色。
* **预期输出:** sRGB(0.5f, 0.5f, 0.0f, 1.0f)

对于 `TEST(BlinkColor, HueInterpolation)` 中的第一个测试用例：

* **假设输入:**
    * `value1`: 60.0f (度)
    * `value2`: 330.0f (度)
    * `percentage`: 0.0f
    * `method`: `Color::HueInterpolationMethod::kShorter`
* **逻辑推理:** 从 60 度插值到 330 度，插值比例为 0%，使用 `shorter` 方法，意味着取起始值。
* **预期输出:** 60.0f

**用户或编程常见的使用错误：**

1. **颜色空间理解错误:** 用户可能不理解不同颜色空间的特性，导致在不合适的颜色空间中进行混合或插值，产生意想不到的颜色结果。
   * **例子:** 假设用户想在感知均匀的颜色空间中混合颜色以获得更平滑的过渡，但错误地在 sRGB 空间中进行混合。

2. **`color-mix()` 百分比错误:**  `color-mix()` 函数的百分比指定的是第二个颜色的比例。初学者可能会弄错，导致混合比例不正确。
   * **例子:**  `color-mix(in srgb, red 70%, blue)`  这里红色占比 70%，蓝色占比 30%。如果理解反了，结果会出错。

3. **Hue 插值方法选择不当:**  在动画或过渡中，选择不同的 hue 插值方法（shorter, longer, increasing, decreasing）会产生不同的颜色变化路径。错误的选择可能导致颜色闪烁或不自然的过渡。
   * **例子:**  在从蓝色过渡到红色时，如果使用 `longer` 插值，可能会经过绿色，而使用 `shorter` 则会直接经过紫色。

4. **忘记处理 Alpha:**  在进行颜色操作时，忘记考虑 alpha 透明度可能导致颜色混合或插值的结果不符合预期。
   * **例子:**  混合两个半透明的颜色时，如果不考虑 alpha 的影响，可能会得到错误的最终透明度。

5. **在不支持的颜色空间中使用 `color-mix()` 或颜色函数:**  虽然 CSS Color Module Level 4 引入了许多新的颜色空间，但并非所有浏览器都完全支持。使用不支持的颜色空间可能导致颜色显示异常。

**总结（针对第 1 部分）：**

`color_test.cc` 文件的第 1 部分主要集中在测试 `blink::Color` 类的**颜色混合 (`ColorMix`)** 和**颜色插值 (`ColorInterpolation`)** 的核心功能，以及 **Hue 插值** 和 **转换为 Skia 颜色格式的验证**。这些测试覆盖了在同一颜色空间和不同颜色空间下进行颜色操作的关键逻辑，并间接验证了颜色空间转换的正确性。 这些功能与 CSS 的 `color-mix()` 函数、颜色动画和过渡、以及对各种颜色空间的支持密切相关。文件中也包含了对带有 "none" 值的颜色处理的测试用例。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/color_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (c) 2022, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/platform/graphics/color.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {
namespace {

using ::testing::TestParamInfo;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

Color CreateSRGBColor(float r, float g, float b, float a) {
  return Color::FromColorSpace(Color::ColorSpace::kSRGB, r, g, b, a);
}

// Helper struct for testing purposes.
struct ColorMixTest {
  Color::ColorSpace mix_space;
  std::optional<Color::HueInterpolationMethod> hue_method;
  Color color_left;
  Color color_right;
  float percentage_right;
  float alpha_multiplier;
  Color color_expected;
};

// Helper struct for testing purposes.
struct ColorTest {
  Color color;
  Color color_expected;
};
}  // namespace

TEST(BlinkColor, ColorMixSameColorSpace) {
  ColorMixTest color_mix_tests[] = {
      {Color::ColorSpace::kSRGB, std::nullopt,
       CreateSRGBColor(1.0f, 0.0f, 0.0f, 1.0f),
       CreateSRGBColor(0.0f, 1.0f, 0.0f, 1.0f),
       /*percentage =*/0.5f, /*alpha_multiplier=*/1.0f,
       CreateSRGBColor(0.5f, 0.5f, 0.0f, 1.0f)},
      {Color::ColorSpace::kSRGB, std::nullopt,
       Color::FromColorSpace(Color::ColorSpace::kRec2020, 0.7919771358198009f,
                             0.23097568481079767f, 0.07376147493817597f, 1.0f),
       Color::FromColorSpace(Color::ColorSpace::kLab, 87.81853633115202f,
                             -79.27108223854806f, 80.99459785152247f, 1.0f),
       /*percentage =*/0.5f, /*alpha_multiplier=*/1.0f,
       CreateSRGBColor(0.5f, 0.5f, 0.0f, 1.0f)},
      {Color::ColorSpace::kSRGB, std::nullopt,
       CreateSRGBColor(1.0f, 0.0f, 0.0f, 1.0f),
       CreateSRGBColor(0.0f, 1.0f, 0.0f, 1.0f),
       /*percentage =*/0.25f, /*alpha_multiplier=*/0.5f,
       CreateSRGBColor(0.75f, 0.25f, 0.0f, 0.5f)},
      // Value obtained form the spec https://www.w3.org/TR/css-color-5/.
      {Color::ColorSpace::kSRGB, std::nullopt,
       CreateSRGBColor(1.0f, 0.0f, 0.0f, 0.7f),
       CreateSRGBColor(0.0f, 1.0f, 0.0f, 0.2f),
       /*percentage =*/0.75f, /*alpha_multiplier=*/1.0f,
       CreateSRGBColor(0.53846f, 0.46154f, 0.0f, 0.325f)}};
  for (auto& color_mix_test : color_mix_tests) {
    Color result = Color::FromColorMix(
        color_mix_test.mix_space, color_mix_test.hue_method,
        color_mix_test.color_left, color_mix_test.color_right,
        color_mix_test.percentage_right, color_mix_test.alpha_multiplier);
    EXPECT_EQ(result.GetColorSpace(), color_mix_test.mix_space);
    SkColor4f resultSkColor = result.toSkColor4f();
    SkColor4f expectedSkColor = color_mix_test.color_expected.toSkColor4f();
    EXPECT_NEAR(resultSkColor.fR, expectedSkColor.fR, 0.001f)
        << "Mixing " << color_mix_test.color_left.toSkColor4f().fR << " "
        << color_mix_test.color_left.toSkColor4f().fG << " "
        << color_mix_test.color_left.toSkColor4f().fB << " "
        << color_mix_test.color_left.toSkColor4f().fA << " and "
        << color_mix_test.color_right.toSkColor4f().fR << " "
        << color_mix_test.color_right.toSkColor4f().fG << " "
        << color_mix_test.color_right.toSkColor4f().fB << " "
        << color_mix_test.color_right.toSkColor4f().fA << " produced "
        << resultSkColor.fR << " " << resultSkColor.fG << " "
        << resultSkColor.fB << " " << resultSkColor.fA
        << " and it was expecting " << expectedSkColor.fR << " "
        << expectedSkColor.fG << " " << expectedSkColor.fB << " "
        << expectedSkColor.fA;
    EXPECT_NEAR(resultSkColor.fG, expectedSkColor.fG, 0.001f)
        << "Mixing " << color_mix_test.color_left.toSkColor4f().fR << " "
        << color_mix_test.color_left.toSkColor4f().fG << " "
        << color_mix_test.color_left.toSkColor4f().fB << " "
        << color_mix_test.color_left.toSkColor4f().fA << " and "
        << color_mix_test.color_right.toSkColor4f().fR << " "
        << color_mix_test.color_right.toSkColor4f().fG << " "
        << color_mix_test.color_right.toSkColor4f().fB << " "
        << color_mix_test.color_right.toSkColor4f().fA << " produced "
        << resultSkColor.fR << " " << resultSkColor.fG << " "
        << resultSkColor.fB << " " << resultSkColor.fA
        << " and it was expecting " << expectedSkColor.fR << " "
        << expectedSkColor.fG << " " << expectedSkColor.fB << " "
        << expectedSkColor.fA;
    EXPECT_NEAR(resultSkColor.fB, expectedSkColor.fB, 0.001f)
        << "Mixing " << color_mix_test.color_left.toSkColor4f().fR << " "
        << color_mix_test.color_left.toSkColor4f().fG << " "
        << color_mix_test.color_left.toSkColor4f().fB << " "
        << color_mix_test.color_left.toSkColor4f().fA << " and "
        << color_mix_test.color_right.toSkColor4f().fR << " "
        << color_mix_test.color_right.toSkColor4f().fG << " "
        << color_mix_test.color_right.toSkColor4f().fB << " "
        << color_mix_test.color_right.toSkColor4f().fA << " produced "
        << resultSkColor.fR << " " << resultSkColor.fG << " "
        << resultSkColor.fB << " " << resultSkColor.fA
        << " and it was expecting " << expectedSkColor.fR << " "
        << expectedSkColor.fG << " " << expectedSkColor.fB << " "
        << expectedSkColor.fA;
    EXPECT_NEAR(resultSkColor.fA, expectedSkColor.fA, 0.001f)
        << "Mixing " << color_mix_test.color_left.toSkColor4f().fR << " "
        << color_mix_test.color_left.toSkColor4f().fG << " "
        << color_mix_test.color_left.toSkColor4f().fB << " "
        << color_mix_test.color_left.toSkColor4f().fA << " and "
        << color_mix_test.color_right.toSkColor4f().fR << " "
        << color_mix_test.color_right.toSkColor4f().fG << " "
        << color_mix_test.color_right.toSkColor4f().fB << " "
        << color_mix_test.color_right.toSkColor4f().fA << " produced "
        << resultSkColor.fR << " " << resultSkColor.fG << " "
        << resultSkColor.fB << " " << resultSkColor.fA
        << " and it was expecting " << expectedSkColor.fR << " "
        << expectedSkColor.fG << " " << expectedSkColor.fB << " "
        << expectedSkColor.fA;
  }
}

TEST(BlinkColor, ColorMixNone) {
  Color color1 = Color::FromColorSpace(Color::ColorSpace::kXYZD50, std::nullopt,
                                       0.5f, std::nullopt, 1.0f);
  Color color2 = Color::FromColorSpace(Color::ColorSpace::kXYZD50, std::nullopt,
                                       std::nullopt, 0.7f, 1.0f);

  Color result = Color::FromColorMix(
      Color::ColorSpace::kXYZD50, /*hue_method=*/std::nullopt, color1, color2,
      /*percentage=*/0.5f, /*alpha_multiplier=*/1.0f);

  EXPECT_EQ(result.param0_is_none_, true);
  EXPECT_EQ(result.param1_is_none_, false);
  EXPECT_EQ(result.param1_, color1.param1_);
  EXPECT_EQ(result.param2_is_none_, false);
  EXPECT_EQ(result.param2_, color2.param2_);
}

TEST(BlinkColor, ColorInterpolation) {
  struct ColorsTest {
    Color color1;
    Color color2;
    Color::ColorSpace space;
    std::optional<Color::HueInterpolationMethod> hue_method;
    float percentage;
    Color expected;
  };

  // Tests extracted from the CSS Color 4 spec, among others.
  // https://csswg.sesse.net/css-color-4/#interpolation-alpha
  ColorsTest colors_test[] = {
      {Color::FromColorSpace(Color::ColorSpace::kSRGB, std::nullopt, 0.12f,
                             0.98f, 1.0f),
       Color::FromColorSpace(Color::ColorSpace::kSRGB, 0.62f, 0.26f, 0.64f,
                             1.0f),
       Color::ColorSpace::kSRGB, std::nullopt, 0.5f,
       Color::FromColorSpace(Color::ColorSpace::kSRGB, 0.62f, 0.19f, 0.81f,
                             1.0f)},

      {Color::FromColorSpace(Color::ColorSpace::kHSL, std::nullopt, 0.5f, 0.5f,
                             1.0f),
       Color::FromColorSpace(Color::ColorSpace::kHSL, 180.0f, 0.1f, 0.1f, 1.0f),
       Color::ColorSpace::kHSL, std::nullopt, 0.5f,
       Color::FromColorSpace(Color::ColorSpace::kHSL, 180.0f, 0.3f, 0.3f,
                             1.0f)},

      {Color::FromColorSpace(Color::ColorSpace::kHWB, std::nullopt, 0.5f, 0.5f,
                             1.0f),
       Color::FromColorSpace(Color::ColorSpace::kHWB, 180.0f, 0.1f, 0.1f, 1.0f),
       Color::ColorSpace::kHWB, std::nullopt, 0.5f,
       Color::FromColorSpace(Color::ColorSpace::kHWB, 180.0f, 0.3f, 0.3f,
                             1.0f)},

      {Color::FromColorSpace(Color::ColorSpace::kSRGB, 0.5f, std::nullopt, 1.0f,
                             1.0f),
       Color::FromColorSpace(Color::ColorSpace::kSRGB, 1.0f, 0.5f, 0.0f, 1.0f),
       Color::ColorSpace::kSRGB, std::nullopt, 0.5f,
       Color::FromColorSpace(Color::ColorSpace::kSRGB, 0.75f, 0.5f, 0.5f,
                             1.0f)},

      {Color::FromColorSpace(Color::ColorSpace::kSRGB, .5f, 0.0f, 0.0f,
                             std::nullopt),
       Color::FromColorSpace(Color::ColorSpace::kSRGB, 1.f, 0.5f, 1.0f, 1.0f),
       Color::ColorSpace::kSRGB, std::nullopt, 0.5f,
       Color::FromColorSpace(Color::ColorSpace::kSRGB, 0.75f, 0.25f, 0.5f,
                             1.0f)},

      {Color::FromColorSpace(Color::ColorSpace::kSRGB, 0.24f, 0.12f, 0.98f,
                             0.4f),
       Color::FromColorSpace(Color::ColorSpace::kSRGB, 0.62f, 0.26f, 0.64f,
                             0.6f),
       Color::ColorSpace::kSRGB, std::nullopt, 0.5f,
       Color::FromColorSpace(Color::ColorSpace::kSRGB, 0.468f, 0.204f, 0.776f,
                             0.5f)},

      {Color::FromColorSpace(Color::ColorSpace::kSRGB, 0.76f, 0.62f, 0.03f,
                             0.4f),
       Color::FromColorSpace(Color::ColorSpace::kDisplayP3, 0.84f, 0.19f, 0.72f,
                             0.6f),
       Color::ColorSpace::kLab, std::nullopt, 0.5f,
       Color::FromColorSpace(Color::ColorSpace::kLab, 58.873f, 51.552f, 7.108f,
                             0.5f)},

      {Color::FromColorSpace(Color::ColorSpace::kSRGB, 0.76f, 0.62f, 0.03f,
                             0.4f),
       Color::FromColorSpace(Color::ColorSpace::kDisplayP3, 0.84f, 0.19f, 0.72f,
                             0.6f),
       Color::ColorSpace::kLch, Color::HueInterpolationMethod::kShorter, 0.5f,
       Color::FromColorSpace(Color::ColorSpace::kLch, 58.873f, 81.126f, 31.82f,
                             0.5f)}};

  for (auto& color_test : colors_test) {
    Color result = Color::InterpolateColors(
        color_test.space, color_test.hue_method, color_test.color1,
        color_test.color2, color_test.percentage);
    EXPECT_NEAR(result.param0_, color_test.expected.param0_, 0.01f)
        << "Mixing \n"
        << color_test.color1.param0_is_none_ << ' ' << color_test.color1.param0_
        << " " << color_test.color1.param1_is_none_ << ' '
        << color_test.color1.param1_ << " " << color_test.color1.param2_is_none_
        << ' ' << color_test.color1.param2_ << " "
        << color_test.color1.alpha_is_none_ << ' ' << color_test.color1.alpha_
        << " and \n"
        << color_test.color2.param0_is_none_ << ' ' << color_test.color2.param0_
        << " " << color_test.color2.param1_is_none_ << ' '
        << color_test.color2.param1_ << " " << color_test.color2.param2_is_none_
        << ' ' << color_test.color2.param2_ << " "
        << color_test.color2.alpha_is_none_ << ' ' << color_test.color2.alpha_
        << " produced\n"
        << result.param0_is_none_ << ' ' << result.param0_ << " "
        << result.param1_is_none_ << ' ' << result.param1_ << " "
        << result.param2_is_none_ << ' ' << result.param2_ << " "
        << result.alpha_is_none_ << ' ' << result.alpha_
        << " and it was expecting \n"
        << color_test.expected.param0_is_none_ << ' '
        << color_test.expected.param0_ << " "
        << color_test.expected.param1_is_none_ << ' '
        << color_test.expected.param1_ << " "
        << color_test.expected.param2_is_none_ << ' '
        << color_test.expected.param2_ << " "
        << color_test.expected.alpha_is_none_ << ' '
        << color_test.expected.alpha_;
    EXPECT_NEAR(result.param1_, color_test.expected.param1_, 0.01f)
        << "Mixing \n"
        << color_test.color1.param0_is_none_ << ' ' << color_test.color1.param0_
        << " " << color_test.color1.param1_is_none_ << ' '
        << color_test.color1.param1_ << " " << color_test.color1.param2_is_none_
        << ' ' << color_test.color1.param2_ << " "
        << color_test.color1.alpha_is_none_ << ' ' << color_test.color1.alpha_
        << " \n"
        << color_test.color2.param0_is_none_ << ' ' << color_test.color2.param0_
        << " " << color_test.color2.param1_is_none_ << ' '
        << color_test.color2.param1_ << " " << color_test.color2.param2_is_none_
        << ' ' << color_test.color2.param2_ << " "
        << color_test.color2.alpha_is_none_ << ' ' << color_test.color2.alpha_
        << " produced \n"
        << result.param0_is_none_ << ' ' << result.param0_ << " "
        << result.param1_is_none_ << ' ' << result.param1_ << " "
        << result.param2_is_none_ << ' ' << result.param2_ << " "
        << result.alpha_is_none_ << ' ' << result.alpha_
        << " and it was expecting \n"
        << color_test.expected.param0_is_none_ << ' '
        << color_test.expected.param0_ << " "
        << color_test.expected.param1_is_none_ << ' '
        << color_test.expected.param1_ << " "
        << color_test.expected.param2_is_none_ << ' '
        << color_test.expected.param2_ << " "
        << color_test.expected.alpha_is_none_ << ' '
        << color_test.expected.alpha_;
    EXPECT_NEAR(result.param2_, color_test.expected.param2_, 0.01f)
        << "Mixing \n"
        << color_test.color1.param0_is_none_ << ' ' << color_test.color1.param0_
        << " " << color_test.color1.param1_is_none_ << ' '
        << color_test.color1.param1_ << " " << color_test.color1.param2_is_none_
        << ' ' << color_test.color1.param2_ << " "
        << color_test.color1.alpha_is_none_ << ' ' << color_test.color1.alpha_
        << " \n"
        << color_test.color2.param0_is_none_ << ' ' << color_test.color2.param0_
        << " " << color_test.color2.param1_is_none_ << ' '
        << color_test.color2.param1_ << " " << color_test.color2.param2_is_none_
        << ' ' << color_test.color2.param2_ << " "
        << color_test.color2.alpha_is_none_ << ' ' << color_test.color2.alpha_
        << " produced \n"
        << result.param0_is_none_ << ' ' << result.param0_ << " "
        << result.param1_is_none_ << ' ' << result.param1_ << " "
        << result.param2_is_none_ << ' ' << result.param2_ << " "
        << result.alpha_is_none_ << ' ' << result.alpha_
        << " and it was expecting \n"
        << color_test.expected.param0_is_none_ << ' '
        << color_test.expected.param0_ << " "
        << color_test.expected.param1_is_none_ << ' '
        << color_test.expected.param1_ << " "
        << color_test.expected.param2_is_none_ << ' '
        << color_test.expected.param2_ << " "
        << color_test.expected.alpha_is_none_ << ' '
        << color_test.expected.alpha_;
    EXPECT_NEAR(result.alpha_, color_test.expected.alpha_, 0.01f)
        << "Mixing \n"
        << color_test.color1.param0_is_none_ << ' ' << color_test.color1.param0_
        << " " << color_test.color1.param1_is_none_ << ' '
        << color_test.color1.param1_ << " " << color_test.color1.param2_is_none_
        << ' ' << color_test.color1.param2_ << " "
        << color_test.color1.alpha_is_none_ << ' ' << color_test.color1.alpha_
        << " \n"
        << color_test.color2.param0_is_none_ << ' ' << color_test.color2.param0_
        << " " << color_test.color2.param1_is_none_ << ' '
        << color_test.color2.param1_ << " " << color_test.color2.param2_is_none_
        << ' ' << color_test.color2.param2_ << " "
        << color_test.color2.alpha_is_none_ << ' ' << color_test.color2.alpha_
        << " produced \n"
        << result.param0_is_none_ << ' ' << result.param0_ << " "
        << result.param1_is_none_ << ' ' << result.param1_ << " "
        << result.param2_is_none_ << ' ' << result.param2_ << " "
        << result.alpha_is_none_ << ' ' << result.alpha_
        << " and it was expecting \n"
        << color_test.expected.param0_is_none_ << ' '
        << color_test.expected.param0_ << " "
        << color_test.expected.param1_is_none_ << ' '
        << color_test.expected.param1_ << " "
        << color_test.expected.param2_is_none_ << ' '
        << color_test.expected.param2_ << " "
        << color_test.expected.alpha_is_none_ << ' '
        << color_test.expected.alpha_;
  }
}

TEST(BlinkColor, HueInterpolation) {
  struct HueTest {
    float value1;
    float value2;
    float percentage;
    Color::HueInterpolationMethod method;
    float expected;
  };

  auto HueMethodToString = [](Color::HueInterpolationMethod method) {
    switch (method) {
      case Color::HueInterpolationMethod::kShorter:
        return "shorter";
      case Color::HueInterpolationMethod::kLonger:
        return "kLonger";
      case Color::HueInterpolationMethod::kIncreasing:
        return "kIncreasing";
      case Color::HueInterpolationMethod::kDecreasing:
        return "kDecreasing";
    }
  };

  HueTest hue_tests[] = {
      {60.0f, 330.0f, 0.0f, Color::HueInterpolationMethod::kShorter, 60.0f},
      {60.0f, 330.0f, 1.0f, Color::HueInterpolationMethod::kShorter, 330.0f},
      {60.0f, 330.0f, 0.7f, Color::HueInterpolationMethod::kShorter, 357.0f},
      {60.0f, 330.0f, 0.0f, Color::HueInterpolationMethod::kLonger, 60.0f},
      {60.0f, 330.0f, 1.0f, Color::HueInterpolationMethod::kLonger, 330.0f},
      {60.0f, 330.0f, 0.7f, Color::HueInterpolationMethod::kLonger, 249.0f},
      {60.0f, 330.0f, 0.0f, Color::HueInterpolationMethod::kIncreasing, 60.0f},
      {60.0f, 330.0f, 1.0f, Color::HueInterpolationMethod::kIncreasing, 330.0f},
      {60.0f, 330.0f, 0.7f, Color::HueInterpolationMethod::kIncreasing, 249.0f},
      {60.0f, 330.0f, 0.0f, Color::HueInterpolationMethod::kDecreasing, 60.0f},
      {60.0f, 330.0f, 1.0f, Color::HueInterpolationMethod::kDecreasing, 330.0f},
      {60.0f, 330.0f, 0.7f, Color::HueInterpolationMethod::kDecreasing, 357.0f},
      {60.0f, 90.0f, 0.0f, Color::HueInterpolationMethod::kShorter, 60.0f},
      {60.0f, 90.0f, 1.0f, Color::HueInterpolationMethod::kShorter, 90.0f},
      {60.0f, 90.0f, 0.7f, Color::HueInterpolationMethod::kShorter, 81.0f},
      {60.0f, 90.0f, 0.0f, Color::HueInterpolationMethod::kLonger, 60.0f},
      {60.0f, 90.0f, 1.0f, Color::HueInterpolationMethod::kLonger, 90.0f},
      {60.0f, 90.0f, 0.7f, Color::HueInterpolationMethod::kLonger, 189.0f},
      {60.0f, 90.0f, 0.0f, Color::HueInterpolationMethod::kIncreasing, 60.0f},
      {60.0f, 90.0f, 1.0f, Color::HueInterpolationMethod::kIncreasing, 90.0f},
      {60.0f, 90.0f, 0.7f, Color::HueInterpolationMethod::kIncreasing, 81.0f},
      {60.0f, 90.0f, 0.0f, Color::HueInterpolationMethod::kDecreasing, 60.0f},
      {60.0f, 90.0f, 1.0f, Color::HueInterpolationMethod::kDecreasing, 90.0f},
      {60.0f, 90.0f, 0.7f, Color::HueInterpolationMethod::kDecreasing, 189.0f},
  };

  for (auto& hue_test : hue_tests) {
    float result = Color::HueInterpolation(
        hue_test.value1, hue_test.value2, hue_test.percentage, hue_test.method);

    EXPECT_NEAR(result, hue_test.expected, 0.01f)
        << hue_test.value1 << ' ' << hue_test.value2 << ' '
        << hue_test.percentage << ' ' << HueMethodToString(hue_test.method)
        << " produced " << result << " but was expecting " << hue_test.expected;
  }
}

TEST(BlinkColor, toSkColor4fValidation) {
  struct ColorFunctionValues {
    Color::ColorSpace color_space;
    float param0;
    float param1;
    float param2;
  };

  ColorFunctionValues color_function_values[] = {
      {Color::ColorSpace::kSRGB, 1.0f, 0.7f, 0.2f},
      {Color::ColorSpace::kSRGBLinear, 1.0f, 0.7f, 0.2f},
      {Color::ColorSpace::kDisplayP3, 1.0f, 0.7f, 0.2f},
      {Color::ColorSpace::kA98RGB, 1.0f, 0.7f, 0.2f},
      {Color::ColorSpace::kProPhotoRGB, 1.0f, 0.7f, 0.2f},
      {Color::ColorSpace::kRec2020, 1.0f, 0.7f, 0.2f},
      {Color::ColorSpace::kXYZD50, 1.0f, 0.7f, 0.2f},
      {Color::ColorSpace::kXYZD65, 1.0f, 0.7f, 0.2f},
      {Color::ColorSpace::kLab, 87.82f, -79.3f, 80.99f},
      {Color::ColorSpace::kOklab, 0.421f, 0.165f, -0.1f},
      {Color::ColorSpace::kLch, 29.69f, 56.11f, 327.1f},
      {Color::ColorSpace::kOklch, 0.628f, 0.225f, 0.126f},
      {Color::ColorSpace::kSRGBLegacy, 0.7f, 0.5f, 0.0f},
      {Color::ColorSpace::kHSL, 4.0f, 0.5f, 0.0f},
      {Color::ColorSpace::kHWB, 4.0f, 0.5f, 0.0f}};

  Color::ColorSpace color_interpolation_space[] = {
      Color::ColorSpace::kXYZD65,     Color::ColorSpace::kXYZD50,
      Color::ColorSpace::kSRGBLinear, Color::ColorSpace::kLab,
      Color::ColorSpace::kOklab,      Color::ColorSpace::kLch,
      Color::ColorSpace::kOklch,      Color::ColorSpace::kSRGB,
      Color::ColorSpace::kSRGBLegacy, Color::ColorSpace::kHSL,
      Color::ColorSpace::kHWB,        Color::ColorSpace::kNone};

  for (auto& space : color_interpolation_space) {
    for (auto& color_function_value : color_function_values) {
      // To validate if the color conversions are done correctly, we will
      // convert all input to SkColor4f and then convert the input to the
      // ColorInterpolationSpace, and then that one to SkColor4f. Those two
      // values should be the same, if the transformations are correct.
      // ToSkColor4f is validate in color_conversions_test.cc.
      Color input;
      input = Color::FromColorSpace(
          color_function_value.color_space, color_function_value.param0,
          color_function_value.param1, color_function_value.param2, 1.0f);

      SkColor4f expected_output = input.toSkColor4f();
      input.ConvertToColorSpace(space);
      SkColor4f output = input.toSkColor4f();

      EXPECT_NEAR(expected_output.fR, output.fR, 0.01f)
          << "Converting from "
          << Color::ColorSpaceToString(color_function_value.color_space)
          << " to " << Color::ColorSpaceToString(space);
      EXPECT_NEAR(expected_output.fG, output.fG, 0.01f)
          << "Converting from "
          << Color::ColorSpaceToString(color_function_value.color_space)
          << " to " << Color::ColorSpaceToString(space);
      EXPECT_NEAR(expected_output.fB, output.fB, 0.01f)
          << "Converting from "
          << Color::ColorSpaceToString(color_function_value.color_space)
          << " to " << Color::ColorSpaceToString(space);
    }
  }
}

TEST(BlinkColor, ExportAsXYZD50Floats) {
  Color::ColorSpace color_spaces[] = {
      Color::ColorSpace::kXYZD65,     Color::ColorSpace::kXYZD50,
      Color::ColorSpace::kSRGBLinear, Color::ColorSpace::kLab,
      Color::ColorSpace::kOklab,      Color::ColorSpace::kLch,
      Color::ColorSpace::kOklch,      Color::ColorSpace::kSRGB,
      Color::ColorSpace::kHSL,        Color::ColorSpace::kHWB,
      Color::ColorSpace::kDisplayP3,  Color::ColorSpace::kProPhotoRGB,
      Color::ColorSpace::kRec2020,    Color::ColorSpace::kA98RGB};

  struct FloatValues {
    float x;
    float y;
    float z;
  };
  FloatValues input_parameters[] = {
      {0.5f, 0.0f, 1.0f},
      {0.6f, 0.2f, 0.2f},
      {0.0f, 0.0f, 0.0f},
      {1.0f, 1.0f, 1.0f},
  };

  for (auto& input_parameter : input_parameters) {
    Color expected =
        Color::FromColorSpace(Color::ColorSpace::kXYZD50, input_parameter.x,
                                 input_parameter.y, input_parameter.z, 1.0f);
    for (auto& space : color_spaces) {
      Color input = Color::FromColorSpace(
          Color::ColorSpace::kXYZD50, input_parameter.x, input_parameter.y,
          input_parameter.z, 1.0f);
      input.ConvertToColorSpace(space);
      auto [x, y, z] = input.ExportAsXYZD50Floats();

      EXPECT_NEAR(x, expected.param0_, 0.01f)
          << "Converting through " << Color::ColorSpaceToString(space);
      EXPECT_NEAR(y, expected.param1_, 0.01f)
          << "Converting through " << Color::ColorSpaceToString(space);
      EXPECT_NEAR(z, expected.param2_, 0.01f)
          << "Converting through " << Color::ColorSpaceToString(space);
    }
  }
}

TEST(BlinkColor, Premultiply) {
  ColorTest color_tests[] = {
      // Testing rectangular-color-space premultiplication.
      {Color::FromColorSpace(Color::ColorSpace::kSRGB, 0.24f, 0.12f, 0.98f,
                             0.4f),
       Color::FromColorSpace(Color::ColorSpace::kSRGB, 0.24f * 0.4f,
                             0.12f * 0.4f, 0.98f * 0.4f, 1.0f)},
      // Testing none value in each component premultiplication.
      {Color::FromColorSpace(Color::ColorSpace::kSRGB, std::nullopt, 0.26f,
                             0.64f, 0.6f),
       Color::FromColorSpace(Color::ColorSpace::kSRGB, std::nullopt,
                             0.26f * 0.6f, 0.64f * 0.6f, 1.0f)},
      {Color::FromColorSpace(Color::ColorSpace::kSRGB, 0.26f, std::nullopt,
                             0.64f, 0.6f),
       Color::FromColorSpace(Color::ColorSpace::kSRGB, 0.26f * 0.6f,
                             std::nullopt, 0.64f * 0.6f, 1.0f)},
      {Color::FromColorSpace(Color::ColorSpace::kSRGB, 0.26f, 0.64f,
                             std::nullopt, 0.6f),
       Color::FromColorSpace(Color::ColorSpace::kSRGB, 0.26f * 0.6f,
                             0.64f * 0.6f, std::nullopt, 1.0f)},
      {Color::FromColorSpace(Color::ColorSpace::kSRGB, 1.0f, 0.8f, 0.0f,
                             std::nullopt),
       Color::FromColorSpace(Color::ColorSpace::kSRGB, 1.0f, 0.8f, 0.0f,
                             std::nullopt)},
      // Testing polar-color-space premultiplication. Hue component should not
      // be premultiplied.
      {Color::FromColorSpace(Color::ColorSpace::kLch, 0.24f, 0.12f, 0.98f,
                             0.4f),
       Color::FromColorSpace(Color::ColorSpace::kLch, 0.24f * 0.4f,
                             0.12f * 0.4f, 0.98f, 1.0f)},
      {Color::FromColorSpace(Color::ColorSpace::kOklch, 0.24f, 0.12f, 0.98f,
                             0.4f),
       Color::FromColorSpace(Color::ColorSpace::kOklch, 0.24f * 0.4f,
                             0.12f * 0.4f, 0.98f, 1.0f)}};

  for (auto& color_test : color_tests) {
    color_test.color.PremultiplyColor();

    if (color_test.color.param0_is_none_) {
      EXPECT_EQ(color_test.color.param0_is_none_,
                color_test.color_expected.param0_is_none_);
    } else {
      EXPECT_NEAR(color_test.color.param0_, color_test.color_expected.param0_,
                  0.001f)
          << "Premultiplying generated " << color_test.color.param0_ << " "
          << color_test.color.param1_ << " " << color_test.color.param2_ << " "
          << color_test.color.alpha_ << " and it was expecting "
          << color_test.color_expected.param0_ << " "
          << color_test.color_expected.param1_ << " "
          << color_test.color_expected.param2_ << " "
          << color_test.color_expected.alpha_;
    }
    if (color_test.color_expected.param1_is_none_) {
      EXPECT_EQ(color_test.color.param1_is_none_,
                color_test.color_expected.param1_is_none_);
    } else {
      EXPECT_NEAR(color_test.color.param1_, color_test.color_expected.param1_,
                  0.001f)
          << "Premultiplying generated " << color_test.color.param0_ << " "
          << color_test.color.param1_ << " " << color_test.color.param2_ << " "
          << color_test.color.alpha_ << " and it was expecting "
          << color_test.color_expected.param0_ << " "
          << color_test.color_expected.param1_ << " "
          << color_test.color_expected.param2_ << " "
          << color_test.color_expected.alpha_;
    }
    if (color_test.color_expected.param2_is_none_) {
      EXPECT_EQ(color_test.color.param2_is_none_,
                color_test.color_expected.param2_is_none_);
    } else {
      EXPECT_NEAR(color_test.color.param2_, color_test.color_expected.param2_,
                  0.001f)
          << "Premultiplying generated " << color_test.color.param0_ << " "
          << color_test.color.param1_ << " " << color_test.color.param2_ << " "
          << color_test.color.alpha_ << " and it was expecting "
          << color_test.color_expected.param0_ << " "
          << color_test.color_expected.param1_ << " "
          << color_test.color_expected.param2_ << " "
          << color_test.color_expected.alpha_;
    }
    if (color_test.color_expected.alpha_is_none_) {
      EXPECT_EQ(color_test.color.alpha_is_none_,
                color_test.color_expected.alpha_is_none_);
    } else {
      EXPECT_NEAR(color_test.color.alpha_, color_test.color_expected.alpha_,
                  0.001f)
          << "Premultiplying generated " << color_test.color.param0_ << " "
          << color_test.color.param1_ << " " << color_test.color.param2_ << " "
          << color_test.color.alpha_ << " and it was expecting "
          << color_test.color_expected.param0_ << " "
          << color_test.color_expected.param1_ << " "
          << color_test.color_expected.param2_ << " "
          << color_test.color_expected.alpha_;
    }
  }
}

TEST(BlinkColor, Unpremultiply) {
  ColorTest color_tests[] = {
      {Color::FromColorSpace(Color::ColorSpace::kSRGB, 0.096f, 0.048f,
                                0.392f, 1.0f),
       Color::FromColorSpace(Color::ColorSpace::kSRGB, 0.24f, 0.12f, 0.98f,
                                0.4f)},
      {Color::FromColorSpace(Color::ColorSpace::kSRGB, 0.372f, 0.156f,
                                0.384f, 1.0f),
       Color::FromColorSpace(Color::ColorSpace::kSRGB, 0.62f, 0.26f, 0.64f,
                                0.6f)},
      {Color::FromColorSpace(Color::ColorSpace::kSRGB, 0.5f, 0.4f, 0.0f,
                                1.0f),
       Color::FromColorSpace(Color::ColorSpace::kSRGB, 1.0f, 0.8f, 0.0f,
                                0.5f)}};

  for (auto& color_test : color_tests) {
    color_test.color.alpha_ = color_test.color_expected.alpha_;
    color_test.color.UnpremultiplyColor();

    EXPECT_NEAR(color_test.color.param0_, color_test.color_expected.param0_,
                0.001f)
        << "Unpremultiplying generated " << color_test.color.param0_ << " "
        << color_test.color.param1_ << " " << color_test.color.param2_ << " "
        << color_test.color.alpha_ << " and it was expecting "
        << color_test.color_expected.param0_ << " "
        << color_test.color_expected.param1_ << " "
        << color_test.color_expected.param2_ << " "
        << color_test.color_expected.alpha_;
    EXPECT_NEAR(color_test.color.param1_, color_test.color_expected.param1_,
                0.001f)
        << "Unpremultiplying generated " << color_test.color.param0_ << " "
        << color_test.color.param1_ << " " << color_test.color.param2_ << " "
        << color_test.color.alpha_ << " and it was expecting "
        << color_test.color_expected.param0_ << " "
        << color_test.color_expected.param1_ << " "
        << color_test.color_expected.param2_ << " "
        << color_test.color_expected.alpha_;
    EXPECT_NEAR(color_test.color.param2_, color_test.color_expected.param2_,
                0.001f)
        << "Unpremultiplying g
"""


```