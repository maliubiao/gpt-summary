Response:
The user wants to understand the functionality of the C++ source code file `open_type_math_support_test.cc`. I need to:

1. **Identify the purpose of the file:** Based on the name and the `#include` directives, it's a unit test file for `open_type_math_support.h`. This means it tests the functionality related to OpenType math features.
2. **Summarize the key functionalities tested:**  The test cases cover:
    - Checking for the presence of the MATH table in a font.
    - Retrieving specific math constants from the MATH table.
    - Getting glyph variants (both regular and constructed) for math symbols.
    - Getting glyph parts for constructing larger math symbols.
    - Retrieving italic correction values for glyphs.
3. **Explain the relevance to web technologies (JavaScript, HTML, CSS):**
    - **HTML:**  This code is part of the rendering engine, responsible for correctly displaying mathematical formulas in HTML using the `<math>` tag.
    - **CSS:**  While not directly related to CSS syntax, CSS properties like `font-family` and `font-size` will influence which fonts are used, and thus whether this code is invoked.
    - **JavaScript:** JavaScript can manipulate the DOM, including elements containing math formulas. This code ensures that those formulas are rendered correctly.
4. **Provide examples of logical reasoning:** The tests use specific font files as input and verify the expected output (presence of MATH table, specific constant values, glyph indices, etc.). I need to present a few of these as examples of input and output.
5. **Illustrate common usage errors:**  These errors would typically be on the *user's* side (web developer) or potential errors in the *code* being tested. User errors could be using fonts without MATH tables when expecting math rendering. Potential code errors are handled by the tests themselves (e.g., what happens with a null font object).
这个文件 `open_type_math_support_test.cc` 是 Chromium Blink 引擎的测试文件，专门用于测试 `open_type_math_support.h` 中定义的 OpenType 数学排版支持功能。 其主要功能是：

1. **测试检测字体是否包含 MATH 表的能力:**  `HasMathData` 函数用于检查给定的字体是否包含 OpenType MATH 表。MATH 表是 OpenType 字体中用于存储数学排版相关信息的关键部分。

2. **测试读取 MATH 表中数学常量的能力:** `MathConstant` 函数用于从字体的 MATH 表中读取特定的数学常量值，例如上标/下标的缩小比例、分数线的位置偏移、根号符号的各种参数等。

3. **测试获取数学变体字形 (Math Variants) 的能力:**  `GetGlyphVariantRecords` 函数用于获取指定字符的不同大小的变体字形，这对于渲染可以伸缩的数学符号（如括号、大括号、积分号等）非常重要。

4. **测试获取数学构造字形部件 (Math Parts) 的能力:** `GetGlyphPartRecords` 函数用于获取构成可伸缩数学符号的各个部件，例如顶部、中间重复部分和底部，这样可以将这些部件组合起来渲染任意大小的符号。

5. **测试获取斜体校正 (Italic Correction) 值的能力:** `MathItalicCorrection` 函数用于获取字形的斜体校正值，这对于精细调整数学公式中字符之间的水平间距至关重要。

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 文件是 Blink 渲染引擎的一部分，它负责将 HTML、CSS 和 JavaScript 转换为用户在浏览器中看到的页面。 具体来说，与数学排版相关的部分与以下方面有关：

* **HTML `<math>` 标签:**  HTML 的 `<math>` 标签用于在网页中嵌入数学公式。当浏览器解析到 `<math>` 标签时，Blink 引擎会使用其内部的数学排版引擎来渲染这些公式。`open_type_math_support_test.cc` 中测试的功能正是这个排版引擎的关键组成部分，确保了 `<math>` 标签中的公式能够正确地显示。

* **CSS 字体属性:** CSS 的 `font-family` 属性用于指定要使用的字体。如果指定的字体包含了 MATH 表，那么 Blink 引擎就会利用 `open_type_math_support.h` 中提供的功能来渲染数学公式。例如，如果一个网页使用了支持数学排版的字体（如 MathJax_Main），那么 `open_type_math_support.cc` 中测试的代码就会被调用来获取正确的数学符号和布局信息。

* **JavaScript 操作 DOM:** JavaScript 可以动态地创建和修改 HTML 元素，包括 `<math>` 标签。当 JavaScript 向页面中添加或修改数学公式时，Blink 引擎会重新渲染这些公式，并依赖 `open_type_math_support.h` 提供的功能。

**举例说明:**

假设 HTML 中有以下 `<math>` 代码：

```html
<math>
  <mfrac>
    <mn>1</mn>
    <mn>2</mn>
  </mfrac>
</math>
```

1. **检测字体 (HasMathData):**  当浏览器渲染这个公式时，Blink 引擎会检查当前使用的字体是否包含 MATH 表。`HasMathData` 函数测试的就是这种检测能力。如果字体没有 MATH 表，那么数学公式的渲染可能会出现问题，例如分数线位置不正确，符号大小不合适等。

2. **读取数学常量 (MathConstant):**  为了正确渲染分数，Blink 引擎需要知道一些关键的常量，例如分数线上方和下方的偏移量、分数线的粗细等。`MathConstant` 函数测试了读取这些常量的能力。例如，`kFractionNumeratorShiftUp` 常量决定了分子相对于分数线的位置。测试用例 `MathConstantFractions` 就验证了从特定的字体文件中读取这些常量值是否正确。

3. **获取数学变体字形 (GetGlyphVariantRecords):** 如果公式中包含需要伸缩的符号，例如大的括号：

   ```html
   <math>
     <mrow>
       <mo>(</mo>
       <munderover>
         <mo>&sum;</mo>
         <mrow>
           <mi>i</mi>
           <mo>=</mo>
           <mn>1</mn>
         </mrow>
         <mi>n</mi>
       </munderover>
       <mo>)</mo>
     </mrow>
   </math>
   ```

   为了使括号能够包围整个求和表达式，Blink 引擎需要获取不同大小的括号字形。`GetGlyphVariantRecords` 函数测试了这种能力。测试用例 `MathVariantsWithTable` 展示了如何从包含 MATH 表的字体中获取左括号的不同大小的变体字形。

4. **获取数学构造字形部件 (GetGlyphPartRecords):** 对于一些非常大的可以无限伸缩的符号，字体可能会提供构成这些符号的部件。例如，一个大的花括号可以由顶部、底部和中间的重复部分组成。`GetGlyphPartRecords` 函数测试了获取这些部件信息的能力，以便 Blink 引擎可以将它们组合起来渲染任意高度的花括号。

5. **获取斜体校正值 (MathItalicCorrection):** 在复杂的数学公式中，字符之间的水平间距需要精细调整，以避免字符重叠或间距过大。斜体校正值就是用于调整这种间距的。`MathItalicCorrection` 函数测试了从字体中读取这个值的能力。测试用例 `MathItalicCorrection` 展示了如何获取带有斜体校正值的字形。

**逻辑推理的假设输入与输出:**

**假设输入:** 一个名为 "fraction-numeratorshiftup11000-axisheight1000-rulethickness1000.woff" 的字体文件，该文件包含 MATH 表，并且定义了 `kFractionNumeratorShiftUp` 数学常量的值为 11000。

**输出:**  `MathConstant("fraction-numeratorshiftup11000-axisheight1000-rulethickness1000.woff", OpenTypeMathSupport::MathConstants::kFractionNumeratorShiftUp)`  这个函数调用应该返回一个 `std::optional<float>`，其包含的值为 `11000.0f`。 测试用例 `MathConstantFractions` 中的第一个断言 `EXPECT_FLOAT_EQ(*result, 11000);` 就验证了这种逻辑。

**涉及用户或者编程常见的使用错误:**

1. **用户使用了不包含 MATH 表的字体来显示数学公式:**  这是最常见的错误。如果用户在 CSS 中指定了不支持数学排版的字体，例如一个普通的文本字体，那么 `<math>` 标签中的公式将无法正确渲染，可能会显示为乱码或者简单的符号排列。

   **例子:**

   ```html
   <style>
     body {
       font-family: "Arial"; /* Arial 字体通常不包含 MATH 表 */
     }
   </style>
   <math>
     <mfrac>
       <mn>1</mn>
       <mn>2</mn>
     </mfrac>
   </math>
   ```

   在这种情况下，浏览器可能无法正确渲染分数线，或者分子和分母的位置会不正确。

2. **编程时，传递了空指针 (nullptr) 给 OpenTypeMathSupport 的函数:**  测试用例 `HasMathData` 和 `MathConstantNullOpt` 检查了这种情况。如果在调用 `OpenTypeMathSupport` 的函数时传递了空指针作为字体数据的输入，程序应该能够正确处理，避免崩溃。这些测试用例确保了代码的健壮性。

   **例子 (在 Blink 引擎的开发中):**

   ```c++
   // 错误示例：可能因为某种原因导致 platform_data 为空
   scoped_refptr<FontPlatformData> platform_data = GetFontPlatformData();
   if (platform_data) {
     OpenTypeMathSupport::HasMathData(platform_data->GetHarfBuzzFace());
   } else {
     // 如果没有检查 platform_data 是否为空，直接传递 nullptr 会导致错误
     OpenTypeMathSupport::HasMathData(nullptr);
   }
   ```

   测试用例会捕捉到这类潜在的编程错误，确保当输入无效时，函数能返回合理的默认值或进行适当的错误处理。

### 提示词
```
这是目录为blink/renderer/platform/fonts/opentype/open_type_math_support_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/fonts/opentype/open_type_math_support.h"
#include "base/memory/scoped_refptr.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/fonts/opentype/open_type_math_test_fonts.h"
#include "third_party/blink/renderer/platform/fonts/opentype/open_type_types.h"
#include "third_party/blink/renderer/platform/testing/font_test_base.h"
#include "third_party/blink/renderer/platform/testing/font_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"

namespace blink {

class OpenTypeMathSupportTest : public FontTestBase {
 protected:
  Font CreateMathFont(const String& name, float size = 1000) {
    FontDescription::VariantLigatures ligatures;
    return blink::test::CreateTestFont(
        AtomicString("MathTestFont"),
        blink::test::BlinkWebTestsFontsTestDataPath(String("math/") + name),
        size, &ligatures);
  }

  bool HasMathData(const String& name) {
    return OpenTypeMathSupport::HasMathData(
        CreateMathFont(name).PrimaryFont()->PlatformData().GetHarfBuzzFace());
  }

  std::optional<float> MathConstant(
      const String& name,
      OpenTypeMathSupport::MathConstants constant) {
    Font math = CreateMathFont(name);
    return OpenTypeMathSupport::MathConstant(
        math.PrimaryFont()->PlatformData().GetHarfBuzzFace(), constant);
  }
};

TEST_F(OpenTypeMathSupportTest, HasMathData) {
  // Null parameter.
  EXPECT_FALSE(OpenTypeMathSupport::HasMathData(nullptr));

  // Font without a MATH table.
  EXPECT_FALSE(HasMathData("math-text.woff"));

  // Font with a MATH table.
  EXPECT_TRUE(HasMathData("axisheight5000-verticalarrow14000.woff"));
}

TEST_F(OpenTypeMathSupportTest, MathConstantNullOpt) {
  Font math_text = CreateMathFont("math-text.woff");

  for (int i = OpenTypeMathSupport::MathConstants::kScriptPercentScaleDown;
       i <=
       OpenTypeMathSupport::MathConstants::kRadicalDegreeBottomRaisePercent;
       i++) {
    auto math_constant = static_cast<OpenTypeMathSupport::MathConstants>(i);

    // Null parameter.
    EXPECT_FALSE(OpenTypeMathSupport::MathConstant(nullptr, math_constant));

    // Font without a MATH table.
    EXPECT_FALSE(OpenTypeMathSupport::MathConstant(
        math_text.PrimaryFont()->PlatformData().GetHarfBuzzFace(),
        math_constant));
  }
}

// See third_party/blink/web_tests/external/wpt/mathml/tools/percentscaledown.py
TEST_F(OpenTypeMathSupportTest, MathConstantPercentScaleDown) {
  {
    auto result = MathConstant(
        "scriptpercentscaledown80-scriptscriptpercentscaledown0.woff",
        OpenTypeMathSupport::MathConstants::kScriptPercentScaleDown);
    EXPECT_TRUE(result);
    EXPECT_FLOAT_EQ(*result, .8);
  }

  {
    auto result = MathConstant(
        "scriptpercentscaledown0-scriptscriptpercentscaledown40.woff",
        OpenTypeMathSupport::MathConstants::kScriptScriptPercentScaleDown);
    EXPECT_TRUE(result);
    EXPECT_FLOAT_EQ(*result, .4);
  }
}

// See third_party/blink/web_tests/external/wpt/mathml/tools/fractions.py
TEST_F(OpenTypeMathSupportTest, MathConstantFractions) {
  {
    auto result = MathConstant(
        "fraction-numeratorshiftup11000-axisheight1000-rulethickness1000.woff",
        OpenTypeMathSupport::MathConstants::kFractionNumeratorShiftUp);
    EXPECT_TRUE(result);
    EXPECT_FLOAT_EQ(*result, 11000);
  }

  {
    auto result = MathConstant(
        "fraction-numeratordisplaystyleshiftup2000-axisheight1000-"
        "rulethickness1000.woff",
        OpenTypeMathSupport::MathConstants::
            kFractionNumeratorDisplayStyleShiftUp);
    EXPECT_TRUE(result);
    EXPECT_FLOAT_EQ(*result, 2000);
  }

  {
    auto result = MathConstant(
        "fraction-denominatorshiftdown3000-axisheight1000-rulethickness1000."
        "woff",
        OpenTypeMathSupport::MathConstants::kFractionDenominatorShiftDown);
    EXPECT_TRUE(result);
    EXPECT_FLOAT_EQ(*result, 3000);
  }

  {
    auto result = MathConstant(
        "fraction-denominatordisplaystyleshiftdown6000-axisheight1000-"
        "rulethickness1000.woff",
        OpenTypeMathSupport::MathConstants::
            kFractionDenominatorDisplayStyleShiftDown);
    EXPECT_TRUE(result);
    EXPECT_FLOAT_EQ(*result, 6000);
  }

  {
    auto result = MathConstant(
        "fraction-numeratorgapmin9000-rulethickness1000.woff",
        OpenTypeMathSupport::MathConstants::kFractionNumeratorGapMin);
    EXPECT_TRUE(result);
    EXPECT_FLOAT_EQ(*result, 9000);
  }

  {
    auto result = MathConstant(
        "fraction-numeratordisplaystylegapmin8000-rulethickness1000.woff",
        OpenTypeMathSupport::MathConstants::kFractionNumDisplayStyleGapMin);
    EXPECT_TRUE(result);
    EXPECT_FLOAT_EQ(*result, 8000);
  }

  {
    auto result = MathConstant(
        "fraction-rulethickness10000.woff",
        OpenTypeMathSupport::MathConstants::kFractionRuleThickness);
    EXPECT_TRUE(result);
    EXPECT_FLOAT_EQ(*result, 10000);
  }

  {
    auto result = MathConstant(
        "fraction-denominatorgapmin4000-rulethickness1000.woff",
        OpenTypeMathSupport::MathConstants::kFractionDenominatorGapMin);
    EXPECT_TRUE(result);
    EXPECT_FLOAT_EQ(*result, 4000);
  }

  {
    auto result = MathConstant(
        "fraction-denominatordisplaystylegapmin5000-rulethickness1000.woff",
        OpenTypeMathSupport::MathConstants::kFractionDenomDisplayStyleGapMin);
    EXPECT_TRUE(result);
    EXPECT_FLOAT_EQ(*result, 5000);
  }
}

// See third_party/blink/web_tests/external/wpt/mathml/tools/radicals.py
TEST_F(OpenTypeMathSupportTest, MathConstantRadicals) {
  {
    auto result = MathConstant(
        "radical-degreebottomraisepercent25-rulethickness1000.woff",
        OpenTypeMathSupport::MathConstants::kRadicalDegreeBottomRaisePercent);
    EXPECT_TRUE(result);
    EXPECT_FLOAT_EQ(*result, .25);
  }

  {
    auto result =
        MathConstant("radical-verticalgap6000-rulethickness1000.woff",
                     OpenTypeMathSupport::MathConstants::kRadicalVerticalGap);
    EXPECT_TRUE(result);
    EXPECT_FLOAT_EQ(*result, 6000);
  }

  {
    auto result = MathConstant(
        "radical-displaystyleverticalgap7000-rulethickness1000.woff",
        OpenTypeMathSupport::MathConstants::kRadicalDisplayStyleVerticalGap);
    EXPECT_TRUE(result);
    EXPECT_FLOAT_EQ(*result, 7000);
  }

  {
    auto result =
        MathConstant("radical-rulethickness8000.woff",
                     OpenTypeMathSupport::MathConstants::kRadicalRuleThickness);
    EXPECT_TRUE(result);
    EXPECT_FLOAT_EQ(*result, 8000);
  }

  {
    auto result =
        MathConstant("radical-extraascender3000-rulethickness1000.woff",
                     OpenTypeMathSupport::MathConstants::kRadicalExtraAscender);
    EXPECT_TRUE(result);
    EXPECT_FLOAT_EQ(*result, 3000);
  }

  {
    auto result = MathConstant(
        "radical-kernbeforedegree4000-rulethickness1000.woff",
        OpenTypeMathSupport::MathConstants::kRadicalKernBeforeDegree);
    EXPECT_TRUE(result);
    EXPECT_FLOAT_EQ(*result, 4000);
  }

  {
    auto result = MathConstant(
        "radical-kernafterdegreeminus5000-rulethickness1000.woff",
        OpenTypeMathSupport::MathConstants::kRadicalKernAfterDegree);
    EXPECT_TRUE(result);
    EXPECT_FLOAT_EQ(*result, -5000);
  }
}

TEST_F(OpenTypeMathSupportTest, MathVariantsWithoutTable) {
  Font math = CreateMathFont("math-text.woff");
  auto glyph = math.PrimaryFont()->GlyphForCharacter('A');

  // Horizontal variants.
  {
    auto variants = OpenTypeMathSupport::GetGlyphVariantRecords(
        math.PrimaryFont()->PlatformData().GetHarfBuzzFace(), glyph,
        OpenTypeMathStretchData::StretchAxis::Horizontal);
    EXPECT_EQ(variants.size(), 1u);
    EXPECT_EQ(variants[0], glyph);
  }

  // Vertical variants.
  {
    auto variants = OpenTypeMathSupport::GetGlyphVariantRecords(
        math.PrimaryFont()->PlatformData().GetHarfBuzzFace(), glyph,
        OpenTypeMathStretchData::StretchAxis::Vertical);
    EXPECT_EQ(variants.size(), 1u);
    EXPECT_EQ(variants[0], glyph);
  }

  // Horizontal parts.
  {
    auto parts = OpenTypeMathSupport::GetGlyphPartRecords(
        math.PrimaryFont()->PlatformData().GetHarfBuzzFace(), glyph,
        OpenTypeMathStretchData::StretchAxis::Horizontal);
    EXPECT_TRUE(parts.empty());
  }

  // // Vertical parts.
  {
    auto parts = OpenTypeMathSupport::GetGlyphPartRecords(
        math.PrimaryFont()->PlatformData().GetHarfBuzzFace(), glyph,
        OpenTypeMathStretchData::StretchAxis::Vertical);
    EXPECT_TRUE(parts.empty());
  }
}

// See blink/web_tests/external/wpt/mathml/tools/operator-dictionary.py and
// blink/renderer/platform/fonts/opentype/open_type_math_test_fonts.h.
TEST_F(OpenTypeMathSupportTest, MathVariantsWithTable) {
  Font math = CreateMathFont("operators.woff");
  auto left_brace = math.PrimaryFont()->GlyphForCharacter(kLeftBraceCodePoint);
  auto over_brace = math.PrimaryFont()->GlyphForCharacter(kOverBraceCodePoint);

  // Retrieve glyph indices of stretchy operator's parts.
  Vector<UChar32> v, h;
  retrieveGlyphForStretchyOperators(math, v, h);

  // Vertical variants for vertical operator.
  {
    auto variants = OpenTypeMathSupport::GetGlyphVariantRecords(
        math.PrimaryFont()->PlatformData().GetHarfBuzzFace(), left_brace,
        OpenTypeMathStretchData::StretchAxis::Vertical);
    EXPECT_EQ(variants.size(), 5u);
    EXPECT_EQ(variants[0], left_brace);
    EXPECT_EQ(variants[1], v[0]);
    EXPECT_EQ(variants[2], v[1]);
    EXPECT_EQ(variants[3], v[2]);
    EXPECT_EQ(variants[4], v[3]);
  }

  // Horizontal variants for vertical operator.
  {
    auto variants = OpenTypeMathSupport::GetGlyphVariantRecords(
        math.PrimaryFont()->PlatformData().GetHarfBuzzFace(), left_brace,
        OpenTypeMathStretchData::StretchAxis::Horizontal);
    EXPECT_EQ(variants.size(), 1u);
    EXPECT_EQ(variants[0], left_brace);
  }

  // Horizontal variants for horizontal operator.
  {
    auto variants = OpenTypeMathSupport::GetGlyphVariantRecords(
        math.PrimaryFont()->PlatformData().GetHarfBuzzFace(), over_brace,
        OpenTypeMathStretchData::StretchAxis::Horizontal);
    EXPECT_EQ(variants.size(), 5u);
    EXPECT_EQ(variants[0], over_brace);
    EXPECT_EQ(variants[1], h[0]);
    EXPECT_EQ(variants[2], h[1]);
    EXPECT_EQ(variants[3], h[2]);
    EXPECT_EQ(variants[4], h[3]);
  }

  // Vertical variants for horizontal operator.
  {
    auto variants = OpenTypeMathSupport::GetGlyphVariantRecords(
        math.PrimaryFont()->PlatformData().GetHarfBuzzFace(), over_brace,
        OpenTypeMathStretchData::StretchAxis::Vertical);
    EXPECT_EQ(variants.size(), 1u);
    EXPECT_EQ(variants[0], over_brace);
  }

  // Vertical parts for vertical operator.
  {
    auto parts = OpenTypeMathSupport::GetGlyphPartRecords(
        math.PrimaryFont()->PlatformData().GetHarfBuzzFace(), left_brace,
        OpenTypeMathStretchData::StretchAxis::Vertical);
    EXPECT_EQ(parts.size(), 2u);
    EXPECT_EQ(parts[0].glyph, v[2]);
    EXPECT_FLOAT_EQ(parts[0].start_connector_length, 0);
    EXPECT_FLOAT_EQ(parts[0].end_connector_length, 1000);
    EXPECT_FLOAT_EQ(parts[0].full_advance, 3000);
    EXPECT_EQ(parts[0].is_extender, false);
    EXPECT_EQ(parts[1].glyph, v[1]);
    EXPECT_FLOAT_EQ(parts[1].start_connector_length, 1000);
    EXPECT_FLOAT_EQ(parts[1].end_connector_length, 1000);
    EXPECT_FLOAT_EQ(parts[1].full_advance, 2000);
    EXPECT_EQ(parts[1].is_extender, true);
  }

  // Horizontal parts for vertical operator.
  {
    auto parts = OpenTypeMathSupport::GetGlyphPartRecords(
        math.PrimaryFont()->PlatformData().GetHarfBuzzFace(), left_brace,
        OpenTypeMathStretchData::StretchAxis::Horizontal);
    EXPECT_TRUE(parts.empty());
  }

  // Horizontal parts for horizontal operator.
  {
    auto parts = OpenTypeMathSupport::GetGlyphPartRecords(
        math.PrimaryFont()->PlatformData().GetHarfBuzzFace(), over_brace,
        OpenTypeMathStretchData::StretchAxis::Horizontal);

    EXPECT_EQ(parts.size(), 2u);
    EXPECT_EQ(parts[0].glyph, h[2]);
    EXPECT_FLOAT_EQ(parts[0].start_connector_length, 0);
    EXPECT_FLOAT_EQ(parts[0].end_connector_length, 1000);
    EXPECT_FLOAT_EQ(parts[0].full_advance, 3000);
    EXPECT_EQ(parts[0].is_extender, false);

    EXPECT_EQ(parts[1].glyph, h[1]);
    EXPECT_FLOAT_EQ(parts[1].start_connector_length, 1000);
    EXPECT_FLOAT_EQ(parts[1].end_connector_length, 1000);
    EXPECT_FLOAT_EQ(parts[1].full_advance, 2000);
    EXPECT_EQ(parts[1].is_extender, true);
  }

  // Vertical parts for horizontal operator.
  {
    auto parts = OpenTypeMathSupport::GetGlyphPartRecords(
        math.PrimaryFont()->PlatformData().GetHarfBuzzFace(), over_brace,
        OpenTypeMathStretchData::StretchAxis::Vertical);
    EXPECT_TRUE(parts.empty());
  }
}

// See third_party/blink/web_tests/external/wpt/mathml/tools/largeop.py and
// blink/renderer/platform/fonts/opentype/open_type_math_test_fonts.h
TEST_F(OpenTypeMathSupportTest, MathItalicCorrection) {
  {
    Font math = CreateMathFont(
        "largeop-displayoperatorminheight2000-2AFF-italiccorrection3000.woff");
    Glyph base_glyph =
        math.PrimaryFont()->GlyphForCharacter(kNAryWhiteVerticalBarCodePoint);

    // Retrieve the glyph with italic correction.
    Vector<OpenTypeMathStretchData::GlyphVariantRecord> variants =
        OpenTypeMathSupport::GetGlyphVariantRecords(
            math.PrimaryFont()->PlatformData().GetHarfBuzzFace(), base_glyph,
            OpenTypeMathStretchData::StretchAxis::Vertical);
    EXPECT_EQ(variants.size(), 3u);
    EXPECT_EQ(variants[0], base_glyph);
    EXPECT_EQ(variants[1], base_glyph);
    Glyph glyph_with_italic_correction = variants[2];

    // MathItalicCorrection with a value.
    std::optional<float> glyph_with_italic_correction_value =
        OpenTypeMathSupport::MathItalicCorrection(
            math.PrimaryFont()->PlatformData().GetHarfBuzzFace(),
            glyph_with_italic_correction);
    EXPECT_TRUE(glyph_with_italic_correction_value);
    EXPECT_FLOAT_EQ(*glyph_with_italic_correction_value, 3000);

    // GetGlyphPartRecords does not set italic correction when there is no
    // construction available.
    float italic_correction = -1000;
    Vector<OpenTypeMathStretchData::GlyphPartRecord> parts =
        OpenTypeMathSupport::GetGlyphPartRecords(
            math.PrimaryFont()->PlatformData().GetHarfBuzzFace(), base_glyph,
            OpenTypeMathStretchData::StretchAxis::Vertical, &italic_correction);
    EXPECT_TRUE(parts.empty());
    EXPECT_FLOAT_EQ(italic_correction, -1000);
  }

  {
    Font math = CreateMathFont(
        "largeop-displayoperatorminheight7000-2AFF-italiccorrection5000.woff");
    Glyph base_glyph =
        math.PrimaryFont()->GlyphForCharacter(kNAryWhiteVerticalBarCodePoint);

    // OpenTypeMathSupport::GetGlyphPartRecords sets italic correction.
    float italic_correction = -1000;
    Vector<OpenTypeMathStretchData::GlyphPartRecord> parts =
        OpenTypeMathSupport::GetGlyphPartRecords(
            math.PrimaryFont()->PlatformData().GetHarfBuzzFace(), base_glyph,
            OpenTypeMathStretchData::StretchAxis::Vertical, &italic_correction);
    EXPECT_EQ(parts.size(), 3u);
    EXPECT_FLOAT_EQ(italic_correction, 5000);
  }
}

TEST_F(OpenTypeMathSupportTest, MathItalicCorrectionNullOpt) {
  // Font without a MATH table.
  Font math_text = CreateMathFont("math-text.woff");
  Glyph glyph = math_text.PrimaryFont()->GlyphForCharacter('A');
  EXPECT_TRUE(glyph);
  EXPECT_FALSE(OpenTypeMathSupport::MathItalicCorrection(
      math_text.PrimaryFont()->PlatformData().GetHarfBuzzFace(), glyph));
}

}  // namespace blink
```