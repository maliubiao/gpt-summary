Response:
The user wants a summary of the provided C++ code file. The file name suggests it's a test file for the CSS property parser in the Blink rendering engine.

I need to identify the main purpose of the code and its relationships to web technologies like JavaScript, HTML, and CSS. I should also look for examples of logic, potential user errors, and how a user's actions could lead to these tests. Finally, I need to ensure the summary covers the functionality of *this specific part* of the file, as the user indicated this is part 1 of 2.

**High-level plan:**

1. Identify the core functionality: testing CSS property parsing.
2. Relate this to CSS functionality and give examples.
3. Analyze the test structure (using `TEST` macros, assertions).
4. Identify tested CSS features (e.g., `paint()`, grid properties, colors, gradients, `image-set()`).
5. Explain how these features relate to CSS, and how users might interact with them (writing CSS rules).
6. Find examples of input and expected output within the tests.
7. Consider common user errors when writing CSS.
8. Describe the user actions that would trigger the CSS parsing (loading a webpage).
9. Focus the summary on the functionalities demonstrated in *this specific snippet*.
这个C++代码文件 `css_property_parser_test.cc` 的主要功能是**测试 Blink 渲染引擎中 CSS 属性解析器的正确性**。

它通过编写一系列的单元测试，来验证 `CSSPropertyParser` 类在解析各种 CSS 属性值时的行为是否符合预期。这些测试覆盖了不同的 CSS 语法、数据类型和函数。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件直接关联着 **CSS** 的功能，因为它测试的是 CSS 属性值的解析。而 CSS 又与 **HTML** 和 **JavaScript** 紧密相关：

*   **HTML (HyperText Markup Language):** HTML 定义了网页的结构和内容。HTML 元素可以通过 `style` 属性或者 `<style>` 标签引入 CSS 样式。这个测试文件验证了当浏览器解析这些样式时，CSS 属性值是否被正确理解。

    *   **举例:**  用户在 HTML 中写下 `<div style="background-image: paint(my-paint-function);"></div>`，浏览器会调用 CSS 解析器来理解 `background-image` 属性的值 `paint(my-paint-function)`。这个测试文件中的 `CSSPaint_Functions` 测试用例就是在验证这种 `paint()` 函数的解析是否正确。

*   **CSS (Cascading Style Sheets):** CSS 用于描述 HTML 元素如何被显示。这个测试文件关注的是 CSS 属性值的解析，例如颜色值、长度单位、函数等。

    *   **举例:**  用户在 CSS 中设置 `grid-template-columns: repeat(3, 1fr);`，浏览器需要解析 `repeat()` 函数和 `1fr` 单位。这个测试文件中的 `GridTrackLimit1` 等测试用例就是在测试 `repeat()` 函数的解析逻辑。

*   **JavaScript:** JavaScript 可以通过 DOM API 操作 HTML 元素的样式。例如，可以使用 `element.style.backgroundColor = 'rgba(255, 0, 0, 0.5)';` 来设置背景颜色。虽然这个测试文件本身不直接测试 JavaScript 代码，但它确保了当 JavaScript 修改样式时，底层 CSS 解析器能够正确处理这些值。

    *   **间接关系:** 当 JavaScript 修改元素的 `style` 属性时，Blink 引擎会再次触发 CSS 解析过程。这个测试文件保证了这个解析过程的正确性。

**逻辑推理的假设输入与输出:**

测试用例中包含了大量的逻辑推理，其基本模式是：

*   **假设输入 (CSS 属性值字符串):** 提供一个 CSS 属性值字符串给解析器。
*   **预期输出:** 期望解析器能够正确地解析这个字符串，或者在解析失败时返回特定的结果（例如 `nullptr`）。

**一些具体的例子:**

*   **假设输入:** `"paint(foo, func1(1px, 3px), red)"` (用于 `background-image` 属性)
    *   **预期输出:** 解析成功，生成一个表示 `paint()` 函数的 CSSValue 对象。
*   **假设输入:** `"repeat(999, 20px)"` (用于 `grid-template-columns` 属性)
    *   **预期输出:**  `ComputeNumberOfTracks` 函数返回 `999`，表示成功解析出 999 个轨道。
*   **假设输入:** `"rgba(0, 0, 0, 1)"` (用于 `background-color` 属性)
    *   **预期输出:** 解析成功，生成一个表示黑色（Color::kBlack）的 CSSColor 对象。
*   **假设输入:** `"paint(foo bar)"` (用于 `background-image` 属性)
    *   **预期输出:** 解析失败，返回 `nullptr`，因为 `paint()` 函数的参数格式不正确。

**涉及用户或者编程常见的使用错误及举例说明:**

这个测试文件间接地反映了用户在编写 CSS 时可能遇到的错误，并验证了解析器如何处理这些错误：

*   **CSS 语法错误:** 用户可能会拼写错误 CSS 关键字、遗漏标点符号或使用错误的参数。
    *   **举例:**  `CSSPaint_InvalidFormat` 测试用例测试了 `paint(foo bar)` 这种错误的格式，预期解析器会返回失败。
    *   **用户错误:** 用户在 CSS 中写了 `background-image: paint(my paint function);` （缺少逗号），Blink 引擎的 CSS 解析器应该能检测到这个错误。
*   **使用了未实现的或被禁用的特性:** 用户可能尝试使用浏览器不支持的 CSS 特性。
    *   **举例:** `CSSPaint_PaintArgumentsDiabled` 测试用例模拟了 `paint()` 函数参数被禁用的情况，预期解析会失败。
    *   **用户错误:** 用户使用了某个实验性的 CSS 函数，但该函数在当前版本的浏览器中被禁用。
*   **超出限制的值:**  某些 CSS 属性对值的范围有限制。
    *   **举例:** `GridTrackLimit` 系列的测试用例测试了 `repeat()` 函数中重复次数的上限。
    *   **用户错误:** 用户在 `grid-template-columns` 中设置了非常大的 `repeat()` 值，例如 `repeat(1000000000, 1fr);`，Blink 需要处理这种极端情况。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 HTML, CSS 和/或 JavaScript 代码。**
2. **用户在浏览器中打开包含这些代码的网页。**
3. **浏览器开始解析 HTML，构建 DOM 树。**
4. **在解析过程中，遇到 `<style>` 标签或元素的 `style` 属性。**
5. **Blink 引擎的 CSS 解析器被调用，开始解析 CSS 样式规则和属性值。**
6. **`CSSPropertyParser` 类负责解析具体的 CSS 属性值。**
7. **如果 CSS 中包含了 `paint()` 函数，`Grid` 布局相关的属性，颜色值等，那么这个测试文件中对应的测试用例覆盖的代码就会被执行到。**

当开发者在开发 Blink 引擎时，如果修改了 `CSSPropertyParser` 相关的代码，他们会运行这些单元测试来确保修改没有引入 bug，并且新的功能能够正确解析。如果某个测试失败，开发者可以通过调试来追踪代码执行过程，找到问题所在。这个测试文件就成为了一个重要的调试线索。

**功能归纳 (第1部分):**

这个代码文件的第一部分主要专注于测试 `CSSPropertyParser` 类解析以下 CSS 功能的正确性：

*   **`paint()` 函数:**  测试了 `paint()` 函数的基本语法、参数解析以及在特定功能被禁用时的行为。
*   **Grid 布局相关的属性:**  特别是 `grid-template-columns` 和 `grid-template-rows` 中 `repeat()` 函数的参数限制，以及 `grid-column-start`, `grid-column-end`, `grid-row-start`, `grid-row-end` 等属性的整数值限制。
*   **颜色值:** 测试了 `rgba()` 颜色函数的解析。
*   **`clip-path` 属性中的 `ellipse()` 形状函数:**  测试了不同参数情况下的解析，并检查了相关 WebFeature 的使用计数。
*   **各种 CSS 函数的使用计数 (UseCounter):**  测试了 `linear-gradient()`, `paint()`, `-webkit-cross-fade()` 等函数在 CSS 中使用时，是否正确地进行了 WebFeature 的计数。
*   **`overflow` 属性的 `overlay` 值:** 测试了 `overflow`, `overflow-x`, `overflow-y` 属性中使用 `overlay` 值的计数情况，以及双值 `overflow` 的计数情况。
*   **其他 CSS 属性值的合法性:** 例如 `src` 属性在 `@font-face` 描述符中的合法值。

总而言之，这部分测试主要关注于验证 CSS 属性解析器对于特定 CSS 函数、Grid 布局特性、颜色以及一些特殊 CSS 值的解析是否正确，并确保这些特性的使用能够被正确地统计。

### 提示词
```
这是目录为blink/renderer/core/css/parser/css_property_parser_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/parser/css_property_parser.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/css_color.h"
#include "third_party/blink/renderer/core/css/css_grid_integer_repeat_value.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_image_set_value.h"
#include "third_party/blink/renderer/core/css/css_repeat_style_value.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/css_to_length_conversion_data.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token_stream.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

static int ComputeNumberOfTracks(const CSSValueList* value_list) {
  int number_of_tracks = 0;
  for (auto& value : *value_list) {
    if (value->IsGridLineNamesValue()) {
      continue;
    }
    if (auto* repeat_value =
            DynamicTo<cssvalue::CSSGridIntegerRepeatValue>(*value)) {
      number_of_tracks +=
          repeat_value->Repetitions() * ComputeNumberOfTracks(repeat_value);
      continue;
    }
    ++number_of_tracks;
  }
  return number_of_tracks;
}

static bool IsValidPropertyValueForStyleRule(CSSPropertyID property_id,
                                             const String& value) {
  CSSParserTokenStream stream(value);
  HeapVector<CSSPropertyValue, 64> parsed_properties;
  return CSSPropertyParser::ParseValue(
      property_id, /*allow_important_annotation=*/false, stream,
      StrictCSSParserContext(SecureContextMode::kSecureContext),
      parsed_properties, StyleRule::RuleType::kStyle);
}

TEST(CSSPropertyParserTest, CSSPaint_Functions) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kBackgroundImage, "paint(foo, func1(1px, 3px), red)",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  ASSERT_TRUE(value);
  ASSERT_TRUE(value->IsValueList());
  EXPECT_EQ(value->CssText(), "paint(foo, func1(1px, 3px), red)");
}

TEST(CSSPropertyParserTest, CSSPaint_NoArguments) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kBackgroundImage, "paint(foo)",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  ASSERT_TRUE(value);
  ASSERT_TRUE(value->IsValueList());
  EXPECT_EQ(value->CssText(), "paint(foo)");
}

TEST(CSSPropertyParserTest, CSSPaint_ValidArguments) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kBackgroundImage, "paint(bar, 10px, red)",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  ASSERT_TRUE(value);
  ASSERT_TRUE(value->IsValueList());
  EXPECT_EQ(value->CssText(), "paint(bar, 10px, red)");
}

TEST(CSSPropertyParserTest, CSSPaint_InvalidFormat) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kBackgroundImage, "paint(foo bar)",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  // Illegal format should not be parsed.
  ASSERT_FALSE(value);
}

TEST(CSSPropertyParserTest, CSSPaint_TrailingComma) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kBackgroundImage, "paint(bar, 10px, red,)",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  ASSERT_FALSE(value);
}

TEST(CSSPropertyParserTest, CSSPaint_PaintArgumentsDiabled) {
  ScopedCSSPaintAPIArgumentsForTest css_paint_api_arguments(false);
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kBackgroundImage, "paint(bar, 10px, red)",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  ASSERT_FALSE(value);
}

TEST(CSSPropertyParserTest, GridTrackLimit1) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kGridTemplateColumns, "repeat(999, 20px)",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  EXPECT_EQ(ComputeNumberOfTracks(To<CSSValueList>(value)), 999);
}

TEST(CSSPropertyParserTest, GridTrackLimit2) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kGridTemplateRows, "repeat(999, 20px)",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  EXPECT_EQ(ComputeNumberOfTracks(To<CSSValueList>(value)), 999);
}

TEST(CSSPropertyParserTest, GridTrackLimit3) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kGridTemplateColumns, "repeat(1000000, 10%)",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  EXPECT_EQ(ComputeNumberOfTracks(To<CSSValueList>(value)), 1000000);
}

TEST(CSSPropertyParserTest, GridTrackLimit4) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kGridTemplateRows, "repeat(1000000, 10%)",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  EXPECT_EQ(ComputeNumberOfTracks(To<CSSValueList>(value)), 1000000);
}

TEST(CSSPropertyParserTest, GridTrackLimit5) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kGridTemplateColumns,
      "repeat(1000000, [first] min-content [last])",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  EXPECT_EQ(ComputeNumberOfTracks(To<CSSValueList>(value)), 1000000);
}

TEST(CSSPropertyParserTest, GridTrackLimit6) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kGridTemplateRows,
      "repeat(1000000, [first] min-content [last])",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  EXPECT_EQ(ComputeNumberOfTracks(To<CSSValueList>(value)), 1000000);
}

TEST(CSSPropertyParserTest, GridTrackLimit7) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kGridTemplateColumns, "repeat(1000001, auto)",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  EXPECT_EQ(ComputeNumberOfTracks(To<CSSValueList>(value)), 1000001);
}

TEST(CSSPropertyParserTest, GridTrackLimit8) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kGridTemplateRows, "repeat(1000001, auto)",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  EXPECT_EQ(ComputeNumberOfTracks(To<CSSValueList>(value)), 1000001);
}

TEST(CSSPropertyParserTest, GridTrackLimit9) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kGridTemplateColumns,
      "repeat(400000, 2em minmax(10px, max-content) 0.5fr)",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  EXPECT_EQ(ComputeNumberOfTracks(To<CSSValueList>(value)), 1200000);
}

TEST(CSSPropertyParserTest, GridTrackLimit10) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kGridTemplateRows,
      "repeat(400000, 2em minmax(10px, max-content) 0.5fr)",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  EXPECT_EQ(ComputeNumberOfTracks(To<CSSValueList>(value)), 1200000);
}

TEST(CSSPropertyParserTest, GridTrackLimit11) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kGridTemplateColumns,
      "repeat(600000, [first] 3vh 10% 2fr [nav] 10px auto 1fr 6em [last])",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  EXPECT_EQ(ComputeNumberOfTracks(To<CSSValueList>(value)), 4200000);
}

TEST(CSSPropertyParserTest, GridTrackLimit12) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kGridTemplateRows,
      "repeat(600000, [first] 3vh 10% 2fr [nav] 10px auto 1fr 6em [last])",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  EXPECT_EQ(ComputeNumberOfTracks(To<CSSValueList>(value)), 4200000);
}

TEST(CSSPropertyParserTest, GridTrackLimit13) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kGridTemplateColumns,
      "repeat(100000000000000000000, 10% 1fr)",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  EXPECT_EQ(ComputeNumberOfTracks(To<CSSValueList>(value)), 10000000);
}

TEST(CSSPropertyParserTest, GridTrackLimit14) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kGridTemplateRows,
      "repeat(100000000000000000000, 10% 1fr)",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  EXPECT_EQ(ComputeNumberOfTracks(To<CSSValueList>(value)), 10000000);
}

TEST(CSSPropertyParserTest, GridTrackLimit15) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kGridTemplateColumns,
      "repeat(100000000000000000000, 10% 5em 1fr auto auto 15px min-content)",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  EXPECT_EQ(ComputeNumberOfTracks(To<CSSValueList>(value)), 9999997);
}

TEST(CSSPropertyParserTest, GridTrackLimit16) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kGridTemplateRows,
      "repeat(100000000000000000000, 10% 5em 1fr auto auto 15px min-content)",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  EXPECT_EQ(ComputeNumberOfTracks(To<CSSValueList>(value)), 9999997);
}

static int GetGridPositionInteger(const CSSValue& value) {
  const auto& list = To<CSSValueList>(value);
  DCHECK_EQ(list.length(), static_cast<size_t>(1));
  const auto& primitive_value = To<CSSPrimitiveValue>(list.Item(0));
  DCHECK(primitive_value.IsNumber());
  return primitive_value.ComputeInteger(
      CSSToLengthConversionData(/*element=*/nullptr));
}

TEST(CSSPropertyParserTest, GridPositionLimit1) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kGridColumnStart, "999",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  DCHECK(value);
  EXPECT_EQ(GetGridPositionInteger(*value), 999);
}

TEST(CSSPropertyParserTest, GridPositionLimit2) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kGridColumnEnd, "1000000",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  DCHECK(value);
  EXPECT_EQ(GetGridPositionInteger(*value), 1000000);
}

TEST(CSSPropertyParserTest, GridPositionLimit3) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kGridRowStart, "1000001",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  DCHECK(value);
  EXPECT_EQ(GetGridPositionInteger(*value), 1000001);
}

TEST(CSSPropertyParserTest, GridPositionLimit4) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kGridRowEnd, "5000000000",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  DCHECK(value);
  EXPECT_EQ(GetGridPositionInteger(*value), 10000000);
}

TEST(CSSPropertyParserTest, GridPositionLimit5) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kGridColumnStart, "-999",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  DCHECK(value);
  EXPECT_EQ(GetGridPositionInteger(*value), -999);
}

TEST(CSSPropertyParserTest, GridPositionLimit6) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kGridColumnEnd, "-1000000",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  DCHECK(value);
  EXPECT_EQ(GetGridPositionInteger(*value), -1000000);
}

TEST(CSSPropertyParserTest, GridPositionLimit7) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kGridRowStart, "-1000001",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  DCHECK(value);
  EXPECT_EQ(GetGridPositionInteger(*value), -1000001);
}

TEST(CSSPropertyParserTest, GridPositionLimit8) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kGridRowEnd, "-5000000000",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  DCHECK(value);
  EXPECT_EQ(GetGridPositionInteger(*value), -10000000);
}

TEST(CSSPropertyParserTest, ColorFunction) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kBackgroundColor, "rgba(0, 0, 0, 1)",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  ASSERT_TRUE(value);
  EXPECT_EQ(Color::kBlack, To<cssvalue::CSSColor>(*value).Value());
}

TEST(CSSPropertyParserTest, IncompleteColor) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kBackgroundColor, "rgba(123 45",
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  ASSERT_FALSE(value);
}

TEST(CSSPropertyParserTest, ClipPathEllipse) {
  test::TaskEnvironment task_environment;
  auto dummy_holder = std::make_unique<DummyPageHolder>(gfx::Size(500, 500));
  Document* doc = &dummy_holder->GetDocument();
  Page::InsertOrdinaryPageForTesting(&dummy_holder->GetPage());
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kSecureContext, doc);

  CSSParser::ParseSingleValue(CSSPropertyID::kClipPath,
                              "ellipse(1px 2px at invalid)", context);

  EXPECT_FALSE(doc->IsUseCounted(WebFeature::kBasicShapeEllipseTwoRadius));
  CSSParser::ParseSingleValue(CSSPropertyID::kClipPath, "ellipse(1px 2px)",
                              context);
  EXPECT_TRUE(doc->IsUseCounted(WebFeature::kBasicShapeEllipseTwoRadius));

  EXPECT_FALSE(doc->IsUseCounted(WebFeature::kBasicShapeEllipseNoRadius));
  CSSParser::ParseSingleValue(CSSPropertyID::kClipPath, "ellipse()", context);
  EXPECT_TRUE(doc->IsUseCounted(WebFeature::kBasicShapeEllipseNoRadius));
}

TEST(CSSPropertyParserTest, GradientUseCount) {
  test::TaskEnvironment task_environment;
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Document& document = dummy_page_holder->GetDocument();
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  WebFeature feature = WebFeature::kCSSGradient;
  EXPECT_FALSE(document.IsUseCounted(feature));
  document.documentElement()->setInnerHTML(
      "<style>* { background-image: linear-gradient(red, blue); }</style>");
  EXPECT_TRUE(document.IsUseCounted(feature));
}

TEST(CSSPropertyParserTest, PaintUseCount) {
  test::TaskEnvironment task_environment;
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  dummy_page_holder->GetFrame().Loader().CommitNavigation(
      WebNavigationParams::CreateWithEmptyHTMLForTesting(
          KURL("https://example.com")),
      nullptr /* extra_data */);
  Document& document = dummy_page_holder->GetDocument();
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  WebFeature feature = WebFeature::kCSSPaintFunction;
  EXPECT_FALSE(document.IsUseCounted(feature));
  document.documentElement()->setInnerHTML(
      "<style>span { background-image: paint(geometry); }</style>");
  EXPECT_TRUE(document.IsUseCounted(feature));
}

TEST(CSSPropertyParserTest, CrossFadeUseCount) {
  test::TaskEnvironment task_environment;
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Document& document = dummy_page_holder->GetDocument();
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  WebFeature feature = WebFeature::kWebkitCrossFade;
  EXPECT_FALSE(document.IsUseCounted(feature));
  document.documentElement()->setInnerHTML(
      "<style>div { background-image: -webkit-cross-fade(url('from.png'), "
      "url('to.png'), 0.2); }</style>");
  EXPECT_TRUE(document.IsUseCounted(feature));
}

TEST(CSSPropertyParserTest, TwoValueOverflowOverlayCount) {
  test::TaskEnvironment task_environment;
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Document& document = dummy_page_holder->GetDocument();
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  WebFeature feature = WebFeature::kCSSValueOverflowOverlay;
  WebFeature feature2 = WebFeature::kTwoValuedOverflow;
  EXPECT_FALSE(document.IsUseCounted(feature));
  EXPECT_FALSE(document.IsUseCounted(feature2));
  document.documentElement()->setInnerHTML(
      "<div style=\"height: 10px; width: 10px; overflow: overlay overlay;\">"
      "<div style=\"height: 50px; width: 50px;\"></div></div>");
  EXPECT_TRUE(document.IsUseCounted(feature));
  EXPECT_TRUE(document.IsUseCounted(feature2));
}

TEST(CSSPropertyParserTest, OneValueOverflowOverlayCount) {
  test::TaskEnvironment task_environment;
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Document& document = dummy_page_holder->GetDocument();
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  WebFeature feature = WebFeature::kCSSValueOverflowOverlay;
  WebFeature feature2 = WebFeature::kTwoValuedOverflow;
  EXPECT_FALSE(document.IsUseCounted(feature));
  EXPECT_FALSE(document.IsUseCounted(feature2));
  document.documentElement()->setInnerHTML(
      "<div style=\"height: 10px; width: 10px; overflow: overlay;\">"
      "<div style=\"height: 50px; width: 50px;\"></div></div>");
  EXPECT_TRUE(document.IsUseCounted(feature));
  EXPECT_FALSE(document.IsUseCounted(feature2));
}

TEST(CSSPropertyParserTest, OverflowXOverlayCount) {
  test::TaskEnvironment task_environment;
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Document& document = dummy_page_holder->GetDocument();
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  WebFeature feature = WebFeature::kCSSValueOverflowOverlay;
  WebFeature feature2 = WebFeature::kTwoValuedOverflow;
  EXPECT_FALSE(document.IsUseCounted(feature));
  EXPECT_FALSE(document.IsUseCounted(feature2));
  document.documentElement()->setInnerHTML(
      "<div style=\"height: 10px; width: 10px; overflow-x: overlay;\">"
      "<div style=\"height: 50px; width: 50px;\"></div></div>");
  EXPECT_TRUE(document.IsUseCounted(feature));
  EXPECT_FALSE(document.IsUseCounted(feature2));
}

TEST(CSSPropertyParserTest, OverflowYOverlayCount) {
  test::TaskEnvironment task_environment;
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Document& document = dummy_page_holder->GetDocument();
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  WebFeature feature = WebFeature::kCSSValueOverflowOverlay;
  WebFeature feature2 = WebFeature::kTwoValuedOverflow;
  EXPECT_FALSE(document.IsUseCounted(feature));
  EXPECT_FALSE(document.IsUseCounted(feature2));
  document.documentElement()->setInnerHTML(
      "<div style=\"height: 10px; width: 10px; overflow-y: overlay;\">"
      "<div style=\"height: 50px; width: 50px;\"></div></div>");
  EXPECT_TRUE(document.IsUseCounted(feature));
  EXPECT_FALSE(document.IsUseCounted(feature2));
}

TEST(CSSPropertyParserTest, OverflowFirstValueOverlayCount) {
  test::TaskEnvironment task_environment;
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Document& document = dummy_page_holder->GetDocument();
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  WebFeature feature = WebFeature::kCSSValueOverflowOverlay;
  WebFeature feature2 = WebFeature::kTwoValuedOverflow;
  EXPECT_FALSE(document.IsUseCounted(feature));
  EXPECT_FALSE(document.IsUseCounted(feature2));
  document.documentElement()->setInnerHTML(
      "<div style=\"height: 10px; width: 10px; overflow: overlay scroll;\">"
      "<div style=\"height: 50px; width: 50px;\"></div></div>");
  EXPECT_TRUE(document.IsUseCounted(feature));
  EXPECT_TRUE(document.IsUseCounted(feature2));
}

TEST(CSSPropertyParserTest, OverflowSecondValueOverlayCount) {
  test::TaskEnvironment task_environment;
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Document& document = dummy_page_holder->GetDocument();
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  WebFeature feature = WebFeature::kCSSValueOverflowOverlay;
  WebFeature feature2 = WebFeature::kTwoValuedOverflow;
  EXPECT_FALSE(document.IsUseCounted(feature));
  EXPECT_FALSE(document.IsUseCounted(feature2));
  document.documentElement()->setInnerHTML(
      "<div style=\"height: 10px; width: 10px; overflow: scroll overlay;\">"
      "<div style=\"height: 50px; width: 50px;\"></div></div>");
  EXPECT_TRUE(document.IsUseCounted(feature));
  EXPECT_TRUE(document.IsUseCounted(feature2));
}

TEST(CSSPropertyParserTest, DropFontfaceDescriptor) {
  test::TaskEnvironment task_environment;
  EXPECT_FALSE(
      IsValidPropertyValueForStyleRule(CSSPropertyID::kSrc, "url(blah)"));
  EXPECT_FALSE(
      IsValidPropertyValueForStyleRule(CSSPropertyID::kSrc, "inherit"));
  EXPECT_FALSE(
      IsValidPropertyValueForStyleRule(CSSPropertyID::kSrc, "var(--dummy)"));
}

class CSSPropertyUseCounterTest : public ::testing::Test {
 public:
  void SetUp() override {
    dummy_page_holder_ = std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
    Page::InsertOrdinaryPageForTesting(&dummy_page_holder_->GetPage());
    // Use strict mode.
    GetDocument().SetCompatibilityMode(Document::kNoQuirksMode);
  }
  void TearDown() override { dummy_page_holder_ = nullptr; }

  void ParseProperty(CSSPropertyID property, const char* value_string) {
    const CSSValue* value = CSSParser::ParseSingleValue(
        property, String(value_string),
        MakeGarbageCollected<CSSParserContext>(GetDocument()));
    DCHECK(value);
  }

  bool IsCounted(WebFeature feature) {
    return GetDocument().IsUseCounted(feature);
  }

  Document& GetDocument() { return dummy_page_holder_->GetDocument(); }

 private:
  test::TaskEnvironment task_environment_;
  std::unique_ptr<DummyPageHolder> dummy_page_holder_;
};

TEST_F(CSSPropertyUseCounterTest, CSSPropertyXUnitlessUseCount) {
  WebFeature feature = WebFeature::kSVGGeometryPropertyHasNonZeroUnitlessValue;
  EXPECT_FALSE(IsCounted(feature));
  ParseProperty(CSSPropertyID::kX, "0");
  // Unitless zero should not register.
  EXPECT_FALSE(IsCounted(feature));
  ParseProperty(CSSPropertyID::kX, "42");
  EXPECT_TRUE(IsCounted(feature));
}

TEST_F(CSSPropertyUseCounterTest, CSSPropertyYUnitlessUseCount) {
  WebFeature feature = WebFeature::kSVGGeometryPropertyHasNonZeroUnitlessValue;
  EXPECT_FALSE(IsCounted(feature));
  ParseProperty(CSSPropertyID::kY, "0");
  // Unitless zero should not register.
  EXPECT_FALSE(IsCounted(feature));
  ParseProperty(CSSPropertyID::kY, "42");
  EXPECT_TRUE(IsCounted(feature));
}

TEST_F(CSSPropertyUseCounterTest, CSSPropertyRUnitlessUseCount) {
  WebFeature feature = WebFeature::kSVGGeometryPropertyHasNonZeroUnitlessValue;
  EXPECT_FALSE(IsCounted(feature));
  ParseProperty(CSSPropertyID::kR, "0");
  // Unitless zero should not register.
  EXPECT_FALSE(IsCounted(feature));
  ParseProperty(CSSPropertyID::kR, "42");
  EXPECT_TRUE(IsCounted(feature));
}

TEST_F(CSSPropertyUseCounterTest, CSSPropertyRxUnitlessUseCount) {
  WebFeature feature = WebFeature::kSVGGeometryPropertyHasNonZeroUnitlessValue;
  EXPECT_FALSE(IsCounted(feature));
  ParseProperty(CSSPropertyID::kRx, "0");
  // Unitless zero should not register.
  EXPECT_FALSE(IsCounted(feature));
  ParseProperty(CSSPropertyID::kRx, "42");
  EXPECT_TRUE(IsCounted(feature));
}

TEST_F(CSSPropertyUseCounterTest, CSSPropertyRyUnitlessUseCount) {
  WebFeature feature = WebFeature::kSVGGeometryPropertyHasNonZeroUnitlessValue;
  EXPECT_FALSE(IsCounted(feature));
  ParseProperty(CSSPropertyID::kRy, "0");
  // Unitless zero should not register.
  EXPECT_FALSE(IsCounted(feature));
  ParseProperty(CSSPropertyID::kRy, "42");
  EXPECT_TRUE(IsCounted(feature));
}

TEST_F(CSSPropertyUseCounterTest, CSSPropertyCxUnitlessUseCount) {
  WebFeature feature = WebFeature::kSVGGeometryPropertyHasNonZeroUnitlessValue;
  EXPECT_FALSE(IsCounted(feature));
  ParseProperty(CSSPropertyID::kCx, "0");
  // Unitless zero should not register.
  EXPECT_FALSE(IsCounted(feature));
  ParseProperty(CSSPropertyID::kCx, "42");
  EXPECT_TRUE(IsCounted(feature));
}

TEST_F(CSSPropertyUseCounterTest, CSSPropertyCyUnitlessUseCount) {
  WebFeature feature = WebFeature::kSVGGeometryPropertyHasNonZeroUnitlessValue;
  EXPECT_FALSE(IsCounted(feature));
  ParseProperty(CSSPropertyID::kCy, "0");
  // Unitless zero should not register.
  EXPECT_FALSE(IsCounted(feature));
  ParseProperty(CSSPropertyID::kCy, "42");
  EXPECT_TRUE(IsCounted(feature));
}

TEST_F(CSSPropertyUseCounterTest, UnitlessPresentationAttributesNotCounted) {
  WebFeature feature = WebFeature::kSVGGeometryPropertyHasNonZeroUnitlessValue;
  EXPECT_FALSE(IsCounted(feature));
  GetDocument().body()->setInnerHTML(R"HTML(
    <svg>
      <rect x="42" y="42" rx="42" ry="42"/>
      <circle cx="42" cy="42" r="42"/>
    </svg>
  )HTML");
  EXPECT_FALSE(IsCounted(feature));
}

TEST_F(CSSPropertyUseCounterTest, CSSPropertyContainStyleUseCount) {
  WebFeature feature = WebFeature::kCSSValueContainStyle;
  EXPECT_FALSE(IsCounted(feature));
  ParseProperty(CSSPropertyID::kContain, "strict");
  EXPECT_FALSE(IsCounted(feature));
  ParseProperty(CSSPropertyID::kContain, "content");
  EXPECT_FALSE(IsCounted(feature));
  ParseProperty(CSSPropertyID::kContain, "style paint");
  EXPECT_TRUE(IsCounted(feature));
}

TEST_F(CSSPropertyUseCounterTest, CSSPropertyFontSizeWebkitXxxLargeUseCount) {
  WebFeature feature = WebFeature::kFontSizeWebkitXxxLarge;
  ParseProperty(CSSPropertyID::kFontSize, "xx-small");
  ParseProperty(CSSPropertyID::kFontSize, "larger");
  ParseProperty(CSSPropertyID::kFontSize, "smaller");
  ParseProperty(CSSPropertyID::kFontSize, "10%");
  ParseProperty(CSSPropertyID::kFontSize, "20px");
  EXPECT_FALSE(IsCounted(feature));
  ParseProperty(CSSPropertyID::kFontSize, "-webkit-xxx-large");
  EXPECT_TRUE(IsCounted(feature));
}

TEST_F(CSSPropertyUseCounterTest, CSSPropertyBackgroundImageWebkitImageSet) {
  WebFeature feature = WebFeature::kWebkitImageSet;
  ParseProperty(CSSPropertyID::kBackgroundImage, "none");
  EXPECT_FALSE(IsCounted(feature));
  ParseProperty(CSSPropertyID::kBackgroundImage,
                "-webkit-image-set(url(foo) 2x)");
  EXPECT_TRUE(IsCounted(feature));
}

TEST_F(CSSPropertyUseCounterTest, CSSPropertyBackgroundImageImageSet) {
  WebFeature feature = WebFeature::kImageSet;

  ParseProperty(CSSPropertyID::kBackgroundImage, "none");
  EXPECT_FALSE(IsCounted(feature));

  ParseProperty(CSSPropertyID::kBackgroundImage, "image-set(url(foo) 2x)");
  EXPECT_TRUE(IsCounted(feature));
}

TEST_F(CSSPropertyUseCounterTest, CSSLightDark) {
  WebFeature feature = WebFeature::kCSSLightDark;

  ParseProperty(CSSPropertyID::kBackgroundColor, "pink");
  EXPECT_FALSE(IsCounted(feature));

  ParseProperty(CSSPropertyID::kBackgroundColor, "light-dark(green, lime)");
  EXPECT_TRUE(IsCounted(feature));
}

void TestImageSetParsing(const String& testValue,
                         const String& expectedCssText) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kBackgroundImage, testValue,
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  ASSERT_NE(value, nullptr);

  const CSSValueList* val_list = To<CSSValueList>(value);
  ASSERT_EQ(val_list->length(), 1U);

  const CSSImageSetValue& image_set_value =
      To<CSSImageSetValue>(val_list->First());
  EXPECT_EQ(expectedCssText, image_set_value.CssText());
}

TEST(CSSPropertyParserTest, ImageSetDefaultResolution) {
  TestImageSetParsing("image-set(url(foo))", "image-set(url(\"foo\") 1x)");
}

TEST(CSSPropertyParserTest, ImageSetResolutionUnitX) {
  TestImageSetParsing("image-set(url(foo) 3x)", "image-set(url(\"foo\") 3x)");
}

TEST(CSSPropertyParserTest, ImageSetResolutionUnitDppx) {
  TestImageSetParsing("image-set(url(foo) 3dppx)",
                      "image-set(url(\"foo\") 3dppx)");
}

TEST(CSSPropertyParserTest, ImageSetResolutionUnitDpi) {
  TestImageSetParsing("image-set(url(foo) 96dpi)",
                      "image-set(url(\"foo\") 96dpi)");
}

TEST(CSSPropertyParserTest, ImageSetResolutionUnitDpcm) {
  TestImageSetParsing("image-set(url(foo) 37dpcm)",
                      "image-set(url(\"foo\") 37dpcm)");
}

TEST(CSSPropertyParserTest, ImageSetZeroResolution) {
  TestImageSetParsing("image-set(url(foo) 0x)", "image-set(url(\"foo\") 0x)");
}

TEST(CSSPropertyParserTest, ImageSetCalcResolutionUnitX) {
  TestImageSetParsing("image-set(url(foo) calc(1x))",
                      "image-set(url(\"foo\") calc(1dppx))");
}

TEST(CSSPropertyParserTest, ImageSetCalcNegativerResolution) {
  TestImageSetParsing("image-set(url(foo) calc(-1x))",
                      "image-set(url(\"foo\") calc(-1dppx))");
}

TEST(CSSPropertyParserTest, ImageSetAddCalcResolutionUnitX) {
  TestImageSetParsing("image-set(url(foo) calc(2x + 3x))",
                      "image-set(url(\"foo\") calc(5dppx))");
}

TEST(CSSPropertyParserTest, ImageSetSubCalcResolutionUnitX) {
  TestImageSetParsing("image-set(url(foo) calc(2x - 1x))",
                      "image-set(url(\"foo\") calc(1dppx))");
}

TEST(CSSPropertyParserTest, ImageSetMultCalcResolutionUnitX) {
  TestImageSetParsing("image-set(url(foo) calc(2x * 3))",
                      "image-set(url(\"foo\") calc(6dppx))");
}

TEST(CSSPropertyParserTest, ImageSetMultCalcNegativeResolution) {
  TestImageSetParsing("image-set(url(foo) calc(1 * -1x))",
                      "image-set(url(\"foo\") calc(-1dppx))");
}

TEST(CSSPropertyParserTest, ImageSetMultCalcNegativeNumberResolution) {
  TestImageSetParsing("image-set(url(foo) calc(-1 * 1x))",
                      "image-set(url(\"foo\") calc(-1dppx))");
}

TEST(CSSPropertyParserTest, ImageSetDivCalcResolutionUnitX) {
  TestImageSetParsing("image-set(url(foo) calc(6x / 3))",
                      "image-set(url(\"foo\") calc(2dppx))");
}

TEST(CSSPropertyParserTest, ImageSetAddCalcResolutionUnitDpiWithX) {
  TestImageSetParsing("image-set(url(foo) calc(96dpi + 2x))",
                      "image-set(url(\"foo\") calc(3dppx))");
}

TEST(CSSPropertyParserTest, ImageSetAddCalcResolutionUnitDpiWithDpi) {
  TestImageSetParsing("image-set(url(foo) calc(96dpi + 96dpi))",
                      "image-set(url(\"foo\") calc(2dppx))");
}

TEST(CSSPropertyParserTest, ImageSetSubCalcResolutionUnitDpiFromX) {
  TestImageSetParsing("image-set(url(foo) calc(2x - 96dpi))",
                      "image-set(url(\"foo\") calc(1dppx))");
}

TEST(CSSPropertyParserTest, ImageSetCalcResolutionUnitDppx) {
  TestImageSetParsing("image-set(url(foo) calc(2dppx * 3))",
                      "image-set(url(\"foo\") calc(6dppx))");
}

TEST(CSSPropertyParserTest, ImageSetCalcResolutionUnitDpi) {
  TestImageSetParsing("image-set(url(foo) calc(32dpi * 3))",
                      "image-set(url(\"foo\") calc(1dppx))");
}

TEST(CSSPropertyParserTest, ImageSetCalcResolutionUnitDpcm) {
  TestImageSetParsing("image-set(url(foo) calc(1dpcm * 37.79532))",
                      "image-set(url(\"foo\") calc(1dppx))");
}

TEST(CSSPropertyParserTest, ImageSetCalcMaxInf) {
  TestImageSetParsing("image-set(url(foo) calc(1 * max(INFinity * 3x, 0dpcm)))",
                      "image-set(url(\"foo\") calc(infinity * 1dppx))");
}

TEST(CSSPropertyParserTest, ImageSetCalcMinInf) {
  TestImageSetParsing("image-set(url(foo) calc(1 * min(inFInity * 4x, 0dpi)))",
                      "image-set(url(\"foo\") calc(0dppx))");
}

TEST(CSSPropertyParserTest, ImageSetCalcMinMaxNan) {
  TestImageSetParsing("image-set(url(foo) calc(1dppx * max(0, min(10, NaN))))",
                      "image-set(url(\"foo\") calc(NaN * 1dppx))");
}

TEST(CSSPropertyParserTest, ImageSetCalcClamp) {
  TestImageSetParsing(
      "image-set(url(foo) calc(1dppx * clamp(-Infinity, 0, infinity)))",
      "image-set(url(\"foo\") calc(0dppx))");
}

TEST(CSSPropertyParserTest, ImageSetCalcClampLeft) {
  TestImageSetParsing(
      "image-set(url(foo) calc(1dppx * clamp(0, -Infinity, infinity)))",
      "image-set(url(\"foo\") calc(0dppx))");
}

TEST(CSSPropertyParserTest, ImageSetCalcClampRight) {
  TestImageSetParsing(
      "image-set(url(foo) calc(1dppx * clamp(-Infinity, infinity, 0)))",
      "image-set(url(\"foo\") calc(0dppx))");
}

TEST(CSSPropertyParserTest, ImageSetCalcClampNan) {
  Tes
```