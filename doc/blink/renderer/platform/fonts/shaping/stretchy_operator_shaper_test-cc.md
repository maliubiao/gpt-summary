Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:**  The filename `stretchy_operator_shaper_test.cc` immediately suggests this file tests the `StretchyOperatorShaper` class. The presence of `TEST_F` macros confirms this is a unit test file using Google Test.

2. **Understand the Context:** The path `blink/renderer/platform/fonts/shaping/` indicates this code is part of Blink (Chromium's rendering engine), specifically dealing with font shaping. "Shaping" refers to the process of converting a sequence of characters into a sequence of glyphs (the visual representation of characters) for a particular font. "Stretchy operators" are mathematical symbols (like brackets, arrows, etc.) that can dynamically adjust their size to accommodate the content they enclose.

3. **Examine the Includes:**  The included headers provide valuable clues:
    * `stretchy_operator_shaper.h`:  Confirms the class being tested.
    * `testing/gtest/include/gtest/gtest.h`:  Shows it's a Google Test file.
    * `platform/fonts/font.h`, `platform/fonts/opentype/...`:  Indicates interaction with font objects and OpenType font features, especially related to mathematical typesetting.
    * `shape_result_inline_headers.h`, `shape_result_test_info.h`:  Suggests the tests examine the output of the shaper, likely verifying the generated glyphs and their properties.
    * `platform/testing/...`:  Shows reliance on Blink's testing infrastructure for creating test fonts.
    * `wtf/text/character_names.h`:  Indicates the use of character constants, likely for mathematical symbols.

4. **Analyze the Test Fixture:** The `StretchyOperatorShaperTest` class, derived from `FontTestBase`, sets up the testing environment. The `CreateMathFont` method is a key helper function, allowing easy creation of test fonts from specific files. This is crucial for testing different font scenarios.

5. **Deconstruct the Test Cases (using `TEST_F`):**  Each `TEST_F` macro represents a specific test scenario. Let's analyze the key ones:

    * **`GlyphVariants`:** This test focuses on verifying that the `StretchyOperatorShaper` correctly selects the appropriate glyph variant (a pre-designed glyph of a specific size) for a given target size. It tests both horizontal and vertical stretching. It also tests the assembly of glyphs (using repeating extender parts) for very large sizes.

    * **`GlyphVariantsCenteredOnBaseline`:** This test is similar to `GlyphVariants` but uses a font where glyphs are centered on the baseline. It verifies that the shaper handles this case correctly, especially regarding vertical alignment and descent.

    * **`NonBMPCodePoint`:**  This tests the shaper's ability to handle characters outside the Basic Multilingual Plane (BMP), which is important for supporting a wider range of mathematical symbols.

    * **`MathItalicCorrection`:** This test specifically checks if the shaper correctly retrieves and applies the italic correction information from the font. It examines scenarios with both single glyph variants and glyph assemblies.

6. **Look for Assertions and Expectations:** Inside each test case, `EXPECT_NEAR`, `EXPECT_EQ`, and `EXPECT_FLOAT_EQ` are used to assert conditions about the shaper's output. These checks are crucial for determining if the shaper is working as expected. The test data (target sizes, expected glyphs, advances, etc.) is embedded directly within the test code.

7. **Identify Connections to Web Technologies (HTML, CSS, JavaScript):**  Consider how font shaping and stretchy operators relate to web rendering:

    * **HTML:**  Mathematical content is often represented using MathML in HTML. The `StretchyOperatorShaper` is directly involved in rendering these MathML elements correctly.
    * **CSS:**  While CSS doesn't directly control the *shaping* of individual glyphs within a font, it does influence font selection (`font-family`, `font-size`) and can indirectly trigger the use of the `StretchyOperatorShaper`. The `font-size` directly affects the `target_size` parameter passed to the shaper.
    * **JavaScript:** JavaScript can manipulate the DOM, including MathML elements, which in turn would trigger the rendering pipeline involving the `StretchyOperatorShaper`. JavaScript libraries could also be used to generate or modify MathML content.

8. **Infer Logic and Assumptions:**  The tests make assumptions about how OpenType math fonts are structured and how the shaper should behave based on that structure. The size variants and assembly logic are based on the information encoded in the test fonts. The tests also account for floating-point inaccuracies using `kSizeError`.

9. **Consider Potential User/Programming Errors:** Think about how developers or users might misuse the features being tested:

    * **Incorrect Font:** Using a font that doesn't have the necessary math tables or stretchy operator definitions would lead to incorrect rendering.
    * **Invalid Target Size:**  While the tests cover edge cases like negative and very large target sizes, providing nonsensical or out-of-range sizes *could* theoretically cause issues (though the shaper is designed to be robust).
    * **Font Corruption:** A corrupted font file could lead to unexpected behavior in the shaper.

10. **Structure the Answer:** Organize the findings logically, starting with a high-level summary of the file's purpose and then diving into specifics like test cases, web technology connections, and potential errors. Use clear and concise language, and provide concrete examples where possible.
This C++ source code file, `stretchy_operator_shaper_test.cc`, is a **unit test file** for the `StretchyOperatorShaper` class in the Chromium Blink rendering engine. Its primary function is to **verify the correctness of the `StretchyOperatorShaper` class**, which is responsible for determining the appropriate glyphs and their layout when rendering "stretchy" mathematical operators (like parentheses, brackets, arrows, summation symbols, etc.) in different sizes.

Here's a breakdown of its functionalities:

**1. Testing the Selection of Glyph Variants:**

* **Functionality:**  The `StretchyOperatorShaper` needs to choose the best glyph representation for a stretchy operator based on the desired size. Fonts often provide multiple pre-designed glyphs (variants) of the same operator at different sizes. This test verifies that the shaper correctly picks the smallest variant that is larger than or equal to the target size.
* **Relation to Web Technologies:** This is directly related to how mathematical expressions are rendered in HTML using MathML. When a MathML element like `<mo>(</mo>` (opening parenthesis) needs to be displayed at a certain size, the `StretchyOperatorShaper` determines which glyph from the font to use.
* **Example:**  Imagine the math font has parenthesis glyphs at sizes 10px, 20px, and 30px. If the desired size is 15px, the test verifies that the `StretchyOperatorShaper` selects the 20px glyph.
* **Assumption & Output:**
    * **Input:** A math font with pre-defined stretchy operator variants, a target size for the operator.
    * **Output:** The test asserts that the `StretchyOperatorShaper` returns the expected glyph index and its advance (width).
* **User/Programming Error:** If a math font doesn't provide size variants for a particular stretchy operator, the rendering might fall back to a default glyph, which might not scale well or look appropriate. This test helps ensure the engine correctly utilizes available variants.

**2. Testing the Assembly of Glyph Parts for Large Operators:**

* **Functionality:** When the desired size of a stretchy operator is very large, a single glyph might not be sufficient. The `StretchyOperatorShaper` can assemble the operator from multiple parts (top, middle repeating, bottom). This test verifies that the shaper correctly determines which parts to use and how many repetitions of the middle part are needed. It also checks the overlap between parts.
* **Relation to Web Technologies:**  Again, crucial for MathML rendering. Large integral symbols (∫), summation symbols (∑), or large brackets often require this kind of assembly.
* **Example:**  Consider a very tall bracket. The `StretchyOperatorShaper` might use a top hook, a bottom hook, and several repeating middle segments to construct the bracket at the required height.
* **Assumption & Output:**
    * **Input:** A math font with defined parts for stretchy operators (start, extender, end), a very large target size.
    * **Output:** The test asserts that the `StretchyOperatorShaper` returns the correct sequence of glyph indices for the parts, and their individual advances, to form the assembled operator with the target size.
* **User/Programming Error:**  If the font's math tables are incorrectly defined (e.g., missing extender glyphs or wrong overlap values), the assembled operator might look broken or have incorrect dimensions. This test helps catch such font-related issues.

**3. Testing with Glyphs Centered on the Baseline:**

* **Functionality:** Some fonts might define stretchy operator parts such that their ink extends both above and below the baseline. This test specifically checks if the `StretchyOperatorShaper` handles these cases correctly, ensuring proper vertical alignment.
* **Relation to Web Technologies:** Important for consistent rendering of mathematical expressions across different fonts.
* **Example:** A centrally aligned square root symbol might have ink extending equally above and below the baseline.
* **Assumption & Output:**
    * **Input:** A math font where stretchy operator parts are centered on the baseline, a target size.
    * **Output:** The test verifies the correct glyphs are selected and that the ascent and descent values returned by the shaper are accurate, especially for vertical assemblies where descent should be normalized to zero.

**4. Testing with Non-BMP Code Points:**

* **Functionality:**  This test ensures that the `StretchyOperatorShaper` can handle characters outside the Basic Multilingual Plane (BMP), which are necessary for representing a wider range of mathematical symbols (like some Arabic mathematical operators).
* **Relation to Web Technologies:** Necessary for full Unicode support in MathML rendering.
* **Example:** The test uses the "Arabic Mathematical Operator Hah With Dal" character.
* **Assumption & Output:**
    * **Input:** A math font containing non-BMP stretchy operators, a target size.
    * **Output:** The test verifies that the shaper correctly identifies and shapes the non-BMP character.

**5. Testing Math Italic Correction:**

* **Functionality:** Some stretchy operators have "italic correction" values associated with them. This is a small horizontal adjustment applied when the operator is used in an italic context. This test verifies that the `StretchyOperatorShaper` correctly retrieves and reports this italic correction.
* **Relation to Web Technologies:** Important for the precise visual appearance of mathematical formulas, especially when italic fonts are used for variables.
* **Example:**  A large parenthesis in an italic font might need a slight horizontal shift to align properly with adjacent characters.
* **Assumption & Output:**
    * **Input:** A math font with italic correction information for a stretchy operator.
    * **Output:** The test asserts that the `StretchyOperatorShaper` returns the correct italic correction value.

**Logic and Assumptions (General):**

* The tests assume the existence of specific test fonts (`stretchy.woff`, `stretchy-centered-on-baseline.woff`, `operators.woff`, etc.) with well-defined math tables and stretchy operator data.
* The tests use a small error tolerance (`kSizeError`) for comparing floating-point values due to potential precision issues.
* The tests exercise both vertical and horizontal stretching of operators.
* The tests cover edge cases like zero, negative, and very large target sizes to ensure robustness.

**Common User/Programming Errors (Related to the Tested Functionality):**

* **Using a font that lacks proper math tables:** If a font doesn't have the necessary information about stretchy operators (variants, parts, overlaps, italic correction), the `StretchyOperatorShaper` will not be able to function correctly, leading to incorrect rendering of mathematical expressions.
* **Font corruption:** A corrupted font file could lead to unpredictable behavior in the shaper.
* **Incorrectly specified font size in CSS:**  While the `StretchyOperatorShaper` tries to find the best fit, extremely small or large font sizes might result in poor rendering if the font doesn't have appropriate variants or parts for those sizes.
* **Browser bugs related to MathML implementation:** While this test focuses on the `StretchyOperatorShaper`, other parts of the browser's MathML rendering pipeline could have bugs that interfere with the correct display of stretchy operators.

In summary, `stretchy_operator_shaper_test.cc` is a crucial part of ensuring the accurate and visually pleasing rendering of mathematical expressions in Chromium. It thoroughly tests the logic of the `StretchyOperatorShaper` class under various conditions, contributing to the overall quality and correctness of the browser's rendering engine.

Prompt: 
```
这是目录为blink/renderer/platform/fonts/shaping/stretchy_operator_shaper_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/fonts/shaping/stretchy_operator_shaper.h"
#include "base/memory/scoped_refptr.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/fonts/opentype/open_type_math_test_fonts.h"
#include "third_party/blink/renderer/platform/fonts/opentype/open_type_types.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_inline_headers.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_test_info.h"
#include "third_party/blink/renderer/platform/testing/font_test_base.h"
#include "third_party/blink/renderer/platform/testing/font_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"

namespace blink {

namespace {

float kSizeError = .1;

const ShapeResultTestInfo* TestInfo(const ShapeResult* result) {
  return static_cast<const ShapeResultTestInfo*>(result);
}

}  // namespace

class StretchyOperatorShaperTest : public FontTestBase {
 protected:
  Font CreateMathFont(const String& name, float size = 1000) {
    FontDescription::VariantLigatures ligatures;
    return blink::test::CreateTestFont(
        AtomicString("MathTestFont"),
        blink::test::BlinkWebTestsFontsTestDataPath(String("math/") + name),
        size, &ligatures);
  }
};

// See blink/web_tests/external/wpt/mathml/tools/operator-dictionary.py and
// blink/renderer/platform/fonts/opentype/open_type_math_test_fonts.h.
TEST_F(StretchyOperatorShaperTest, GlyphVariants) {
  Font math = CreateMathFont("stretchy.woff");

  StretchyOperatorShaper vertical_shaper(
      kVerticalArrow, OpenTypeMathStretchData::StretchAxis::Vertical);
  StretchyOperatorShaper horizontal_shaper(
      kHorizontalArrow, OpenTypeMathStretchData::StretchAxis::Horizontal);

  auto vertical_arrow = math.PrimaryFont()->GlyphForCharacter(kVerticalArrow);
  auto horizontal_arrow =
      math.PrimaryFont()->GlyphForCharacter(kHorizontalArrow);

  // Calculate glyph indices of stretchy operator's parts.
  Vector<UChar32> v, h;
  retrieveGlyphForStretchyOperators(math, v, h);

  // Stretch operators to target sizes (in font units) 125, 250, 375, 500, 625,
  // 750, 875, 1000, 1125, ..., 3750, 3875, 4000.
  //
  // Shaper tries glyphs vertical_arrow/horizontal_arrow, h0/v0, h1/v1, h2/v2,
  // h3/v3 of respective sizes 1000, 1000, 2000, 3000 and 4000. It returns the
  // smallest glyph larger than the target size.
  const unsigned size_count = 4;
  const unsigned subdivision = 8;
  for (unsigned i = 0; i < size_count; i++) {
    for (unsigned j = 1; j <= subdivision; j++) {
      // Due to floating-point errors, the actual metrics of the size variants
      // might actually be slightly smaller than expected. Reduce the
      // target_size by kSizeError to ensure that the shaper picks the desired
      // size variant.
      float target_size = i * 1000 + (j * 1000 / subdivision) - kSizeError;

      // Metrics of horizontal size variants.
      {
        StretchyOperatorShaper::Metrics metrics;
        horizontal_shaper.Shape(&math, target_size, &metrics);
        EXPECT_NEAR(metrics.advance, (i + 1) * 1000, kSizeError);
        EXPECT_NEAR(metrics.ascent, 1000, kSizeError);
        EXPECT_FLOAT_EQ(metrics.descent, 0);
      }

      // Metrics of vertical size variants.

      {
        StretchyOperatorShaper::Metrics metrics;
        vertical_shaper.Shape(&math, target_size, &metrics);
        EXPECT_NEAR(metrics.advance, 1000, kSizeError);
        EXPECT_NEAR(metrics.ascent, (i + 1) * 1000, kSizeError);
        EXPECT_FLOAT_EQ(metrics.descent, 0);
      }

      // Shaping of horizontal size variants.
      {
        const ShapeResult* result = horizontal_shaper.Shape(&math, target_size);
        EXPECT_EQ(TestInfo(result)->NumberOfRunsForTesting(), 1u);
        EXPECT_EQ(TestInfo(result)->RunInfoForTesting(0).NumGlyphs(), 1u);
        Glyph expected_variant = i ? h[0] + 2 * i : horizontal_arrow;
        EXPECT_EQ(TestInfo(result)->GlyphForTesting(0, 0), expected_variant);
        EXPECT_NEAR(TestInfo(result)->AdvanceForTesting(0, 0), (i + 1) * 1000,
                    kSizeError);
      }

      // Shaping of vertical size variants.
      {
        const ShapeResult* result = vertical_shaper.Shape(&math, target_size);
        EXPECT_EQ(TestInfo(result)->NumberOfRunsForTesting(), 1u);
        EXPECT_EQ(TestInfo(result)->RunInfoForTesting(0).NumGlyphs(), 1u);
        Glyph expected_variant = i ? v[0] + 2 * i : vertical_arrow;
        EXPECT_EQ(TestInfo(result)->GlyphForTesting(0, 0), expected_variant);
        EXPECT_NEAR(TestInfo(result)->AdvanceForTesting(0, 0), (i + 1) * 1000,
                    kSizeError);
      }
    }
  }

  // Stretch an operator to target sizes (in font units) much larger than 4000.
  //
  // This will force an assembly with the following parts:
  // _____________________________________________________________
  // Part  | MaxStartOverlap | MaxEndOverlap | Advance | Extender |
  // h2/v2 |     0           |    1000       | 3000    |   false  |
  // h1/v1 |    1000         |    1000       | 2000    |   true   |
  //
  // For an assembly made of one non-extender glyph h2/v2 and repetition_count
  // copies of extenders h1/v1, the size is
  // advance(h2/v2) + repetition_count * (advance(h1/v1) - overlap).
  //
  // For repetition_count = k and overlap = 750, the size is X = 1250k + 3000.
  //
  // Since the font min overlap is 500, for repetition_count = k - 1 the size
  // is at most Y = 1500k + 1500.
  //
  // Since the max overlap of parts is 1000, for repetition_count = k + 1 the
  // size is at least Z = 1000k + 4000.
  //
  // { X - 4000 = 1250k - 1000 >= 250 >> kSizeError for k >= 1.
  // { X - Y = 1500 - 250k >= 250 >> kSizeError for k <= 5.
  // Hence setting the target size to 1250k + 3000 will ensure an assembly of
  // k + 1 glyphs and overlap close to 750 for 1 <= k <= 5.
  //
  // Additionally, X - Z = 250k - 1000 = 250 >> kSizeError for k = 5 so this
  // case also verifies that the minimal number of repetitions is actually used.
  //
  for (unsigned repetition_count = 1; repetition_count <= 5;
       repetition_count++) {
    // It is not necessary to decrease the target_size by kSizeError here. The
    // shaper can just increase overlap by kSizeError / repetition_count to
    // reduce the actual size of the assembly.
    float overlap = 750;
    float target_size = 3000 + repetition_count * (2000 - overlap);

    // Metrics of horizontal assembly.
    {
      StretchyOperatorShaper::Metrics metrics;
      horizontal_shaper.Shape(&math, target_size, &metrics);
      EXPECT_NEAR(metrics.advance, target_size, kSizeError);
      EXPECT_NEAR(metrics.ascent, 1000, kSizeError);
      EXPECT_FLOAT_EQ(metrics.descent, 0);
    }

    // Metrics of vertical assembly.
    {
      StretchyOperatorShaper::Metrics metrics;
      vertical_shaper.Shape(&math, target_size, &metrics);
      EXPECT_NEAR(metrics.advance, 1000, kSizeError);
      EXPECT_NEAR(metrics.ascent, target_size, kSizeError);
      EXPECT_FLOAT_EQ(metrics.descent, 0);
    }

    // Shaping of horizontal assembly.
    // From left to right: h2, h1, h1, h1, ...
    {
      const ShapeResult* result = horizontal_shaper.Shape(&math, target_size);

      EXPECT_EQ(TestInfo(result)->NumberOfRunsForTesting(), 1u);
      EXPECT_EQ(TestInfo(result)->RunInfoForTesting(0).NumGlyphs(),
                repetition_count + 1);
      EXPECT_EQ(TestInfo(result)->GlyphForTesting(0, 0), h[2]);
      EXPECT_NEAR(TestInfo(result)->AdvanceForTesting(0, 0), 3000 - overlap,
                  kSizeError);
      for (unsigned i = 0; i < repetition_count - 1; i++) {
        EXPECT_EQ(TestInfo(result)->GlyphForTesting(0, i + 1), h[1]);
        EXPECT_NEAR(TestInfo(result)->AdvanceForTesting(0, i + 1),
                    2000 - overlap, kSizeError);
      }
      EXPECT_EQ(TestInfo(result)->GlyphForTesting(0, repetition_count), h[1]);
      EXPECT_NEAR(TestInfo(result)->AdvanceForTesting(0, repetition_count),
                  2000, kSizeError);
    }

    // Shaping of vertical assembly.
    // From bottom to top: v2, v1, v1, v1, ...
    {
      const ShapeResult* result = vertical_shaper.Shape(&math, target_size);

      EXPECT_EQ(TestInfo(result)->NumberOfRunsForTesting(), 1u);
      EXPECT_EQ(TestInfo(result)->RunInfoForTesting(0).NumGlyphs(),
                repetition_count + 1);
      for (unsigned i = 0; i < repetition_count; i++) {
        EXPECT_EQ(TestInfo(result)->GlyphForTesting(0, i), v[1]);
        EXPECT_NEAR(TestInfo(result)->AdvanceForTesting(0, i), 2000 - overlap,
                    kSizeError);
      }
      EXPECT_EQ(TestInfo(result)->GlyphForTesting(0, repetition_count), v[2]);
      EXPECT_NEAR(TestInfo(result)->AdvanceForTesting(0, repetition_count),
                  3000, kSizeError);
    }
  }

  // Stretch an operator to edge target size values.
  //
  // These tests verify that it does not cause any assertion or crashes.
  {
    // Zero.
    float target_size = 0;
    horizontal_shaper.Shape(&math, target_size);
    vertical_shaper.Shape(&math, target_size);

    // Negative.
    target_size = -5500;
    horizontal_shaper.Shape(&math, target_size);
    vertical_shaper.Shape(&math, target_size);

    // Max limit.
    target_size = std::numeric_limits<float>::max();
    horizontal_shaper.Shape(&math, target_size);
    vertical_shaper.Shape(&math, target_size);

    // Min limit.
    target_size = std::numeric_limits<float>::min();
    horizontal_shaper.Shape(&math, target_size);
    vertical_shaper.Shape(&math, target_size);

    // More than the max number of glyphs.
    // The size of an assembly with one non-extender v2/h2 and k - 1 extenders
    // h1/v1 and minimal overlap 500 is Y = 1500k + 1500.
    // So target_size - Y >= 250 >> kSizeError if the assembly does not have
    // more than the max number of glyphs.
    target_size =
        static_cast<float>(1500 * HarfBuzzRunGlyphData::kMaxGlyphs + 1750);
    horizontal_shaper.Shape(&math, target_size);
    vertical_shaper.Shape(&math, target_size);
  }
}

// This test performs similar checks for shaping glyph assemblies to the ones of
// StretchyOperatorShaperTest.GlyphVariants, but the glyphs involved have their
// ink ascents equal to their ink descents. The glyphs used and their advances
// should remain exactly the same. Horizontal assemblies now use the ink
// ascent/descent of the glyphs but vertical assemblies should be normalized to
// a zero ink descent (see crbug.com/1409380).
TEST_F(StretchyOperatorShaperTest, GlyphVariantsCenteredOnBaseline) {
  Font math = CreateMathFont("stretchy-centered-on-baseline.woff");

  StretchyOperatorShaper vertical_shaper(
      kVerticalArrow, OpenTypeMathStretchData::StretchAxis::Vertical);
  StretchyOperatorShaper horizontal_shaper(
      kHorizontalArrow, OpenTypeMathStretchData::StretchAxis::Horizontal);

  // Calculate glyph indices of stretchy operator's parts.
  Vector<UChar32> v, h;
  retrieveGlyphForStretchyOperators(math, v, h);

  unsigned repetition_count = 5;
  float overlap = 750;
  float target_size = 3000 + repetition_count * (2000 - overlap);

  // Metrics of horizontal assembly.
  {
    StretchyOperatorShaper::Metrics metrics;
    horizontal_shaper.Shape(&math, target_size, &metrics);
    EXPECT_NEAR(metrics.advance, target_size, kSizeError);
    EXPECT_NEAR(metrics.ascent, 500, kSizeError);
    EXPECT_FLOAT_EQ(metrics.descent, 500);
  }

  // Metrics of vertical assembly.
  {
    StretchyOperatorShaper::Metrics metrics;
    vertical_shaper.Shape(&math, target_size, &metrics);
    EXPECT_NEAR(metrics.advance, 1000, kSizeError);
    EXPECT_NEAR(metrics.ascent, target_size, kSizeError);
    EXPECT_FLOAT_EQ(metrics.descent, 0);
  }

  // Shaping of horizontal assembly.
  // From left to right: h2, h1, h1, h1, ...
  {
    const ShapeResult* result = horizontal_shaper.Shape(&math, target_size);

    EXPECT_EQ(TestInfo(result)->NumberOfRunsForTesting(), 1u);
    EXPECT_EQ(TestInfo(result)->RunInfoForTesting(0).NumGlyphs(),
              repetition_count + 1);
    EXPECT_EQ(TestInfo(result)->GlyphForTesting(0, 0), h[2]);
    EXPECT_NEAR(TestInfo(result)->AdvanceForTesting(0, 0), 3000 - overlap,
                kSizeError);
    for (unsigned i = 0; i < repetition_count - 1; i++) {
      EXPECT_EQ(TestInfo(result)->GlyphForTesting(0, i + 1), h[1]);
      EXPECT_NEAR(TestInfo(result)->AdvanceForTesting(0, i + 1), 2000 - overlap,
                  kSizeError);
    }
    EXPECT_EQ(TestInfo(result)->GlyphForTesting(0, repetition_count), h[1]);
    EXPECT_NEAR(TestInfo(result)->AdvanceForTesting(0, repetition_count), 2000,
                kSizeError);
  }

  // Shaping of vertical assembly.
  // From bottom to top: v2, v1, v1, v1, ...
  {
    const ShapeResult* result = vertical_shaper.Shape(&math, target_size);

    EXPECT_EQ(TestInfo(result)->NumberOfRunsForTesting(), 1u);
    EXPECT_EQ(TestInfo(result)->RunInfoForTesting(0).NumGlyphs(),
              repetition_count + 1);
    for (unsigned i = 0; i < repetition_count; i++) {
      EXPECT_EQ(TestInfo(result)->GlyphForTesting(0, i), v[1]);
      EXPECT_NEAR(TestInfo(result)->AdvanceForTesting(0, i), 2000 - overlap,
                  kSizeError);
    }
    EXPECT_EQ(TestInfo(result)->GlyphForTesting(0, repetition_count), v[2]);
    EXPECT_NEAR(TestInfo(result)->AdvanceForTesting(0, repetition_count), 3000,
                kSizeError);
  }
}

// See blink/web_tests/external/wpt/mathml/tools/operator-dictionary.py and
// blink/renderer/platform/fonts/opentype/open_type_math_test_fonts.h.
TEST_F(StretchyOperatorShaperTest, NonBMPCodePoint) {
  Font math = CreateMathFont("operators.woff");

  StretchyOperatorShaper horizontal_shaper(
      kArabicMathematicalOperatorHahWithDal,
      OpenTypeMathStretchData::StretchAxis::Horizontal);

  float target_size = 10000;
  StretchyOperatorShaper::Metrics metrics;
  horizontal_shaper.Shape(&math, target_size, &metrics);
  EXPECT_NEAR(metrics.advance, target_size, kSizeError);
  EXPECT_NEAR(metrics.ascent, 1000, kSizeError);
  EXPECT_FLOAT_EQ(metrics.descent, 0);
}

// See third_party/blink/web_tests/external/wpt/mathml/tools/largeop.py and
// blink/renderer/platform/fonts/opentype/open_type_math_test_fonts.h
TEST_F(StretchyOperatorShaperTest, MathItalicCorrection) {
  {
    Font math = CreateMathFont(
        "largeop-displayoperatorminheight2000-2AFF-italiccorrection3000.woff");
    StretchyOperatorShaper shaper(
        kNAryWhiteVerticalBarCodePoint,
        OpenTypeMathStretchData::StretchAxis::Vertical);

    // Base size.
    StretchyOperatorShaper::Metrics metrics;
    shaper.Shape(&math, 0, &metrics);
    EXPECT_EQ(metrics.italic_correction, 0);

    // Larger variant.
    float target_size = 2000 - kSizeError;
    shaper.Shape(&math, target_size, &metrics);
    EXPECT_EQ(metrics.italic_correction, 3000);
  }

  {
    Font math = CreateMathFont(
        "largeop-displayoperatorminheight7000-2AFF-italiccorrection5000.woff");
    StretchyOperatorShaper shaper(
        kNAryWhiteVerticalBarCodePoint,
        OpenTypeMathStretchData::StretchAxis::Vertical);

    // Base size.
    StretchyOperatorShaper::Metrics metrics;
    shaper.Shape(&math, 0, &metrics);
    EXPECT_EQ(metrics.italic_correction, 0);

    // Glyph assembly.
    float target_size = 7000;
    shaper.Shape(&math, target_size, &metrics);
    EXPECT_EQ(metrics.italic_correction, 5000);
  }
}

}  // namespace blink

"""

```