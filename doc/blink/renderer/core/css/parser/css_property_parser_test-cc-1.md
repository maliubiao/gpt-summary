Response:
The user has provided a C++ source code file for testing CSS property parsing in the Chromium Blink engine. This is the second part of the file. The request is to summarize its functionality, explain its relation to web technologies (JavaScript, HTML, CSS) with examples, discuss logical inferences with examples, identify common user/programming errors, and trace user actions leading to this code.

**Plan:**

1. **Summarize the overall functionality of this code snippet.** Focus on the types of CSS properties being tested.
2. **Explain the relevance to JavaScript, HTML, and CSS.**  Show how these tests relate to how browsers interpret and apply styles.
3. **Identify logical inferences and provide examples.** Look for test cases that validate specific logic in the CSS parsing process.
4. **Point out potential user/programming errors illustrated by the tests.** Focus on invalid CSS syntax or incorrect usage.
5. **Describe the user journey to trigger this code.**  Outline the steps a user might take that eventually lead to the execution of this parsing logic.
这是 `blink/renderer/core/css/parser/css_property_parser_test.cc` 文件的第二部分，延续了第一部分的功能，主要集中在测试 CSS 属性解析器对特定 CSS 属性值的解析能力，特别是与图像和背景相关的属性。

**功能归纳:**

这部分代码延续了第一部分的功能，主要侧重于测试 CSS 属性解析器对以下内容的处理能力：

* **`image-set()` 函数:**  测试 `image-set()` 函数的各种有效和无效的语法，包括：
    * 使用 `url()` 函数和不使用 `url()` 函数。
    * 不同的分辨率单位 (`1x`)。
    * 使用引号和不使用引号的 URL。
    * 嵌套使用渐变函数 (`linear-gradient`, `radial-gradient`, `conic-gradient`, 以及它们的 repeating 版本)。
    * 使用 `type()` 修饰符指定 MIME 类型。
    * 各种解析失败的场景，例如缺少 URL、负分辨率、渐变颜色不足、`calc()` 表达式中缺少单位等。
* **`light-dark()` 函数:** 测试 `light-dark()` 函数在不同上下文中的解析，特别是作为 `background-image` 在 UA (User Agent) 样式表中的特殊处理。
* **`-internal-appearance-auto-base-select()` 函数:** 测试特定于 UA 样式表的内部函数。
* **`revert` 和 `revert-layer` 关键字:** 测试这两个关键字的解析。
* **`background-repeat` 和 `mask-repeat` 属性:** 测试对 `repeat` 关键字及其组合 (例如 `repeat-x`, `repeat-y`, `space`, `round`) 的解析。
* **`mask-position` 属性:** 测试对 `mask-position` 值的解析，包括关键字和带有单位的值。
* **`mask-mode` 属性:** 测试对 `mask-mode` 关键字 (例如 `alpha`, `luminance`, `match-source`) 的解析。
* **`mask` 简写属性:** 测试当 `mask` 属性设置为 `none` 时，其他相关的 `mask-*` 属性的默认值是如何被处理的。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS:**  这部分代码的核心是测试 CSS 语法的解析。`image-set()`, `light-dark()`, `background-repeat`, `mask-position`, `mask-mode`, 和 `mask` 都是 CSS 属性或函数。这些测试确保了 Blink 引擎能够正确理解和应用这些 CSS 规则。
    * **例子:**  `TEST(CSSPropertyParserTest, ImageSetUrlFunction)` 测试了 CSS `image-set(url('foo') 1x)` 是否能被正确解析。 这直接关系到开发者在 CSS 中使用 `image-set` 函数来提供响应式图片资源的能力。
* **HTML:** HTML 元素会通过 `style` 属性或外部 CSS 文件应用 CSS 样式。这些测试保证了当 HTML 中定义了这些 CSS 属性时，浏览器能够正确解析。
    * **例子:**  一个 `<img>` 标签或带有背景图片的 `<div>` 元素，其 CSS 样式中使用了 `image-set()` 或 `background-repeat` 属性，那么这些测试就验证了浏览器是否能正确处理这些样式。
* **JavaScript:** JavaScript 可以用来动态修改 HTML 元素的样式。这些测试确保了当 JavaScript 设置元素的 CSS 属性时，Blink 引擎也能正确解析。
    * **例子:**  使用 JavaScript 的 `element.style.backgroundImage = "image-set(url('small.png') 1x, url('large.png') 2x)";` 这样的代码，其效果依赖于浏览器对 `image-set()` 函数的正确解析，而这正是这些测试所验证的。

**逻辑推理的假设输入与输出:**

这部分测试主要通过 `TestImageSetParsing` 和 `TestImageSetParsingFailure` 函数进行逻辑验证。

* **假设输入 (对于 `TestImageSetParsing`):**  一个表示 CSS 属性值的字符串，例如 `"image-set(url(foo) 1x)"`。
* **预期输出 (对于 `TestImageSetParsing`):**  经过解析器处理后得到的规范化字符串，例如 `"image-set(url(\"foo\") 1x)"`。这表明解析器成功解析了输入，并可能进行了标准化处理（例如添加引号）。

* **假设输入 (对于 `TestImageSetParsingFailure`):** 一个表示无效 CSS 属性值的字符串，例如 `"image-set(1x)"`。
* **预期输出 (对于 `TestImageSetParsingFailure`):**  解析器返回 `nullptr`，表示解析失败。

**用户或编程常见的使用错误举例说明:**

这些测试用例覆盖了开发者在使用 CSS 时可能犯的错误：

* **`image-set()` 函数使用错误:**
    * `TEST(CSSPropertyParserTest, ImageSetMissingUrl)`:  用户可能忘记在 `image-set()` 中提供 URL，例如 `image-set(1x)`.
    * `TEST(CSSPropertyParserTest, ImageSetNegativeResolution)`: 用户可能会错误地提供负分辨率，例如 `image-set(url(foo) -1x)`.
    * `TEST(CSSPropertyParserTest, ImageSetAddCalcMissingUnit1)`: 在 `calc()` 表达式中忘记添加单位，例如 `image-set(url(foo) calc(2 + 3x))`.
* **`light-dark()` 函数使用错误:**
    * `TEST(CSSPropertyParserTest, LightDarkAuthor)` 和 `TEST(CSSPropertyParserTest, UALightDarkBackgroundImage)` 强调了 `light-dark()` 函数在不同上下文中的使用限制，普通开发者可能会在不支持的地方使用它。
* **`background-repeat` 和 `mask-repeat` 属性使用错误:** 虽然这部分代码没有直接展示错误用例，但其测试覆盖了各种有效的组合，暗示了用户可能在使用时混淆或错误组合这些关键字。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户编写 HTML、CSS 或 JavaScript 代码:** 用户在其网页代码中使用了涉及到的 CSS 属性或函数，例如 `image-set`, `light-dark`, `background-repeat`, `mask-position`, `mask-mode`, 或 `mask`。
2. **浏览器加载网页:** 当用户访问包含这些 CSS 代码的网页时，浏览器开始解析 HTML 和 CSS。
3. **CSS 解析器被调用:**  Blink 引擎的 CSS 解析器组件会被调用来处理 CSS 样式。
4. **`CSSPropertyParser::ParseSingleValue` 或 `CSSPropertyParser::ParseValue` 被调用:**  当解析到相关的 CSS 属性时，`css_property_parser_test.cc` 中测试的函数（例如 `CSSPropertyParser::ParseSingleValue`）会被调用，尝试将 CSS 属性值解析成内部表示。
5. **测试用例覆盖了各种情况:** `css_property_parser_test.cc` 中的测试用例模拟了各种可能的 CSS 属性值，包括有效的和无效的，以确保解析器的健壮性。
6. **断言 (ASSERT/EXPECT) 触发:** 如果解析器的行为与预期不符 (例如，应该解析成功的却失败了，或者应该解析失败的却成功了)，测试用例中的断言会失败，这可以作为调试的线索，指示 CSS 解析器可能存在 bug。

**总结这部分的功能:**

这部分 `css_property_parser_test.cc` 文件的主要功能是**系统地测试 Blink 引擎中 CSS 属性解析器对于图像和背景相关属性（特别是 `image-set()`, `light-dark()`, `background-repeat`, `mask-*` 等）的解析逻辑的正确性**。它通过定义各种输入场景（包括有效和无效的 CSS 语法），并断言解析器的输出是否符合预期，来确保浏览器能够准确理解和应用这些 CSS 规则，从而保证网页样式的正确渲染。 这些测试覆盖了常见的用户使用场景以及可能出现的错误，有助于提高浏览器的稳定性和兼容性。

### 提示词
```
这是目录为blink/renderer/core/css/parser/css_property_parser_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
tImageSetParsing(
      "image-set(url(foo) calc(1 * clamp(-INFINITY*0dppx, 0dppx, "
      "infiniTY*0dppx)))",
      "image-set(url(\"foo\") calc(NaN * 1dppx))");
}

TEST(CSSPropertyParserTest, ImageSetUrlFunction) {
  TestImageSetParsing("image-set(url('foo') 1x)", "image-set(url(\"foo\") 1x)");
}

TEST(CSSPropertyParserTest, ImageSetUrlFunctionEmptyStrUrl) {
  TestImageSetParsing("image-set(url('') 1x)", "image-set(url(\"\") 1x)");
}

TEST(CSSPropertyParserTest, ImageSetUrlFunctionNoQuotationMarks) {
  TestImageSetParsing("image-set(url(foo) 1x)", "image-set(url(\"foo\") 1x)");
}

TEST(CSSPropertyParserTest, ImageSetNoUrlFunction) {
  TestImageSetParsing("image-set('foo' 1x)", "image-set(url(\"foo\") 1x)");
}

TEST(CSSPropertyParserTest, ImageSetEmptyStrUrl) {
  TestImageSetParsing("image-set('' 1x)", "image-set(url(\"\") 1x)");
}

TEST(CSSPropertyParserTest, ImageSetLinearGradient) {
  TestImageSetParsing("image-set(linear-gradient(red, blue) 1x)",
                      "image-set(linear-gradient(red, blue) 1x)");
}

TEST(CSSPropertyParserTest, ImageSetRepeatingLinearGradient) {
  TestImageSetParsing("image-set(repeating-linear-gradient(red, blue 25%) 1x)",
                      "image-set(repeating-linear-gradient(red, blue 25%) 1x)");
}

TEST(CSSPropertyParserTest, ImageSetRadialGradient) {
  TestImageSetParsing("image-set(radial-gradient(red, blue) 1x)",
                      "image-set(radial-gradient(red, blue) 1x)");
}

TEST(CSSPropertyParserTest, ImageSetRepeatingRadialGradient) {
  TestImageSetParsing("image-set(repeating-radial-gradient(red, blue 25%) 1x)",
                      "image-set(repeating-radial-gradient(red, blue 25%) 1x)");
}

TEST(CSSPropertyParserTest, ImageSetConicGradient) {
  TestImageSetParsing("image-set(conic-gradient(red, blue) 1x)",
                      "image-set(conic-gradient(red, blue) 1x)");
}

TEST(CSSPropertyParserTest, ImageSetRepeatingConicGradient) {
  TestImageSetParsing("image-set(repeating-conic-gradient(red, blue 25%) 1x)",
                      "image-set(repeating-conic-gradient(red, blue 25%) 1x)");
}

TEST(CSSPropertyParserTest, ImageSetType) {
  TestImageSetParsing("image-set(url('foo') 1x type('image/png'))",
                      "image-set(url(\"foo\") 1x type(\"image/png\"))");
}

void TestImageSetParsingFailure(const String& testValue) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kBackgroundImage, testValue,
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  ASSERT_EQ(value, nullptr);
}

TEST(CSSPropertyParserTest, ImageSetEmpty) {
  TestImageSetParsingFailure("image-set()");
}

TEST(CSSPropertyParserTest, ImageSetMissingUrl) {
  TestImageSetParsingFailure("image-set(1x)");
}

TEST(CSSPropertyParserTest, ImageSetNegativeResolution) {
  TestImageSetParsingFailure("image-set(url(foo) -1x)");
}

TEST(CSSPropertyParserTest, ImageSetOnlyOneGradientColor) {
  TestImageSetParsingFailure("image-set(linear-gradient(red) 1x)");
}

TEST(CSSPropertyParserTest, ImageSetAddCalcMissingUnit1) {
  TestImageSetParsingFailure("image-set(url(foo) calc(2 + 3x))");
}

TEST(CSSPropertyParserTest, ImageSetAddCalcMissingUnit2) {
  TestImageSetParsingFailure("image-set(url(foo) calc(2x + 3))");
}

TEST(CSSPropertyParserTest, ImageSetSubCalcMissingUnit1) {
  TestImageSetParsingFailure("image-set(url(foo) calc(2 - 1x))");
}

TEST(CSSPropertyParserTest, ImageSetSubCalcMissingUnit2) {
  TestImageSetParsingFailure("image-set(url(foo) calc(2x - 1))");
}

TEST(CSSPropertyParserTest, ImageSetMultCalcDoubleX) {
  TestImageSetParsingFailure("image-set(url(foo) calc(2x * 3x))");
}

TEST(CSSPropertyParserTest, ImageSetDivCalcDoubleX) {
  TestImageSetParsingFailure("image-set(url(foo) calc(6x / 3x))");
}

TEST(CSSPropertyParserTest, LightDarkAuthor) {
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  ASSERT_TRUE(CSSParser::ParseSingleValue(
      CSSPropertyID::kColor, "light-dark(#000000, #ffffff)", context));
  ASSERT_TRUE(CSSParser::ParseSingleValue(CSSPropertyID::kColor,
                                          "light-dark(red, green)", context));
  // light-dark() is only valid for background-image in UA sheets.
  ASSERT_FALSE(CSSParser::ParseSingleValue(
      CSSPropertyID::kBackgroundImage,
      "light-dark(url(light.png), url(dark.png))", context));
}

TEST(CSSPropertyParserTest, UALightDarkBackgroundImage) {
  auto* ua_context = MakeGarbageCollected<CSSParserContext>(
      kUASheetMode, SecureContextMode::kInsecureContext);

  const struct {
    const char* value;
    bool valid;
  } tests[] = {
      {"light-dark()", false},
      {"light-dark(url(light.png))", false},
      {"light-dark(url(light.png) url(dark.png))", false},
      {"light-dark(url(light.png),,url(dark.png))", false},
      {"light-dark(url(light.png), url(dark.png))", true},
      {"light-dark(url(light.png), none)", true},
      {"light-dark(none, -webkit-image-set(url(dark.png) 1x))", true},
      {"light-dark(none, image-set(url(dark.png) 1x))", true},
      {"light-dark(  none  ,  none   )", true},
      {"light-dark(  url(light.png)  ,  url(dark.png)   )", true},
  };

  for (const auto& test : tests) {
    EXPECT_EQ(!!CSSParser::ParseSingleValue(CSSPropertyID::kBackgroundImage,
                                            test.value, ua_context),
              test.valid)
        << test.value;
  }
}

TEST(CSSPropertyParserTest, UAAppearanceAutoBaseSelectSerialization) {
  // Note: we're not using CSSParser::ParseSingleValue, because it expects
  // arbitrary function substitution to already have happened.
  const CSSPropertyValueSet* set = css_test_helpers::ParseDeclarationBlock(
      "color:-internal-appearance-auto-base-select(red, blue)", kUASheetMode);
  const CSSValue* value = set->GetPropertyCSSValue(CSSPropertyID::kColor);
  ASSERT_TRUE(value);
  EXPECT_EQ("-internal-appearance-auto-base-select(red, blue)",
            value->CssText());
}

namespace {

bool ParseCSSValue(CSSPropertyID property_id,
                   const String& value,
                   const CSSParserContext* context) {
  CSSParserTokenStream stream(value);
  HeapVector<CSSPropertyValue, 64> parsed_properties;
  return CSSPropertyParser::ParseValue(
      property_id, /*allow_important_annotation=*/false, stream, context,
      parsed_properties, StyleRule::RuleType::kStyle);
}

}  // namespace

TEST(CSSPropertyParserTest, UALightDarkBackgroundShorthand) {
  auto* ua_context = MakeGarbageCollected<CSSParserContext>(
      kUASheetMode, SecureContextMode::kInsecureContext);

  const struct {
    const char* value;
    bool valid;
  } tests[] = {
      {"light-dark()", false},
      {"light-dark(url(light.png))", false},
      {"light-dark(url(light.png) url(dark.png))", false},
      {"light-dark(url(light.png),,url(dark.png))", false},
      {"light-dark(url(light.png), url(dark.png))", true},
      {"light-dark(url(light.png), none)", true},
      {"light-dark(none, -webkit-image-set(url(dark.png) 1x))", true},
      {"light-dark(none, image-set(url(dark.png) 1x))", true},
      {"light-dark(  none  ,  none   )", true},
      {"light-dark(  url(light.png)  ,  url(dark.png)   )", true},
  };

  for (const auto& test : tests) {
    EXPECT_EQ(
        !!ParseCSSValue(CSSPropertyID::kBackground, test.value, ua_context),
        test.valid)
        << test.value;
  }
}

TEST(CSSPropertyParserTest, ParseRevert) {
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);

  String string = " revert";
  CSSParserTokenStream stream(string);

  const CSSValue* value = CSSPropertyParser::ParseSingleValue(
      CSSPropertyID::kMarginLeft, stream, context);
  ASSERT_TRUE(value);
  EXPECT_TRUE(value->IsRevertValue());
}

TEST(CSSPropertyParserTest, ParseRevertLayer) {
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);

  String string = " revert-layer";
  CSSParserTokenStream stream(string);

  const CSSValue* value = CSSPropertyParser::ParseSingleValue(
      CSSPropertyID::kMarginLeft, stream, context);
  ASSERT_TRUE(value);
  EXPECT_TRUE(value->IsRevertLayerValue());
}

void TestRepeatStyleParsing(const String& testValue,
                            const String& expectedCssText,
                            const CSSPropertyID& propID) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      propID, testValue,
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  ASSERT_NE(value, nullptr);

  const CSSValueList* val_list = To<CSSValueList>(value);
  ASSERT_EQ(val_list->length(), 1U);

  const CSSRepeatStyleValue& repeat_style_value =
      To<CSSRepeatStyleValue>(val_list->First());
  EXPECT_EQ(expectedCssText, repeat_style_value.CssText());
}

void TestRepeatStylesParsing(const String& testValue,
                             const String& expectedCssText) {
  TestRepeatStyleParsing(testValue, expectedCssText,
                         CSSPropertyID::kBackgroundRepeat);
  TestRepeatStyleParsing(testValue, expectedCssText,
                         CSSPropertyID::kMaskRepeat);
}

TEST(CSSPropertyParserTest, RepeatStyleRepeatX1) {
  TestRepeatStylesParsing("repeat-x", "repeat-x");
}

TEST(CSSPropertyParserTest, RepeatStyleRepeatX2) {
  TestRepeatStylesParsing("repeat no-repeat", "repeat-x");
}

TEST(CSSPropertyParserTest, RepeatStyleRepeatY1) {
  TestRepeatStylesParsing("repeat-y", "repeat-y");
}

TEST(CSSPropertyParserTest, RepeatStyleRepeatY2) {
  TestRepeatStylesParsing("no-repeat repeat", "repeat-y");
}

TEST(CSSPropertyParserTest, RepeatStyleRepeat1) {
  TestRepeatStylesParsing("repeat", "repeat");
}

TEST(CSSPropertyParserTest, RepeatStyleRepeat2) {
  TestRepeatStylesParsing("repeat repeat", "repeat");
}

TEST(CSSPropertyParserTest, RepeatStyleNoRepeat1) {
  TestRepeatStylesParsing("no-repeat", "no-repeat");
}

TEST(CSSPropertyParserTest, RepeatStyleNoRepeat2) {
  TestRepeatStylesParsing("no-repeat no-repeat", "no-repeat");
}

TEST(CSSPropertyParserTest, RepeatStyleSpace1) {
  TestRepeatStylesParsing("space", "space");
}

TEST(CSSPropertyParserTest, RepeatStyleSpace2) {
  TestRepeatStylesParsing("space space", "space");
}

TEST(CSSPropertyParserTest, RepeatStyleRound1) {
  TestRepeatStylesParsing("round", "round");
}

TEST(CSSPropertyParserTest, RepeatStyleRound2) {
  TestRepeatStylesParsing("round round", "round");
}

TEST(CSSPropertyParserTest, RepeatStyle2Val) {
  TestRepeatStylesParsing("round space", "round space");
}

void TestRepeatStyleViaShorthandParsing(const String& testValue,
                                        const String& expectedCssText,
                                        const CSSPropertyID& propID) {
  auto* style =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLStandardMode);
  CSSParser::ParseValue(style, propID, testValue, false /* important */);
  ASSERT_NE(style, nullptr);
  EXPECT_TRUE(style->AsText().Contains(expectedCssText));
}

void TestRepeatStyleViaShorthandsParsing(const String& testValue,
                                         const String& expectedCssText) {
  TestRepeatStyleViaShorthandParsing(testValue, expectedCssText,
                                     CSSPropertyID::kBackground);
  TestRepeatStyleViaShorthandParsing(testValue, expectedCssText,
                                     CSSPropertyID::kMask);
}

TEST(CSSPropertyParserTest, RepeatStyleRepeatXViaShorthand) {
  TestRepeatStyleViaShorthandsParsing("url(foo) repeat no-repeat", "repeat-x");
}

TEST(CSSPropertyParserTest, RepeatStyleRoundViaShorthand) {
  TestRepeatStyleViaShorthandsParsing("url(foo) round round", "round");
}

TEST(CSSPropertyParserTest, RepeatStyle2ValViaShorthand) {
  TestRepeatStyleViaShorthandsParsing("url(foo) space repeat", "space repeat");
}

void TestMaskPositionParsing(const String& testValue,
                             const String& expectedCssText) {
  auto* style =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLStandardMode);
  CSSParser::ParseValue(style, CSSPropertyID::kMaskPosition, testValue,
                        false /* important */);
  ASSERT_NE(style, nullptr);
  EXPECT_TRUE(style->AsText().Contains(expectedCssText));
}

TEST(CSSPropertyParserTest, MaskPositionCenter) {
  TestMaskPositionParsing("center", "center center");
}

TEST(CSSPropertyParserTest, MaskPositionTopRight) {
  TestMaskPositionParsing("top right", "right top");
}

TEST(CSSPropertyParserTest, MaskPositionBottomLeft) {
  TestMaskPositionParsing("bottom 10% left -13px", "left -13px bottom 10%");
}

void TestMaskModeParsing(const String& testValue,
                         const String& expectedCssText) {
  const CSSValue* value = CSSParser::ParseSingleValue(
      CSSPropertyID::kMaskMode, testValue,
      StrictCSSParserContext(SecureContextMode::kSecureContext));
  ASSERT_NE(value, nullptr);
  EXPECT_EQ(expectedCssText, value->CssText());
}

TEST(CSSPropertyParserTest, MaskModeAlpha) {
  TestMaskModeParsing("alpha", "alpha");
}

TEST(CSSPropertyParserTest, MaskModeLuminance) {
  TestMaskModeParsing("luminance", "luminance");
}

TEST(CSSPropertyParserTest, MaskModeMatchSource) {
  TestMaskModeParsing("match-source", "match-source");
}

TEST(CSSPropertyParserTest, MaskModeMultipleValues) {
  TestMaskModeParsing("alpha, luminance, match-source",
                      "alpha, luminance, match-source");
}

void TestMaskParsing(const String& specified_css_text,
                     const CSSPropertyID property_id,
                     const String& expected_prop_value) {
  auto* style =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLStandardMode);
  ASSERT_NE(style, nullptr);

  auto result = style->ParseAndSetProperty(
      CSSPropertyID::kMask, specified_css_text, false /* important */,
      SecureContextMode::kSecureContext, nullptr /* context_style_sheet */);
  ASSERT_NE(result, MutableCSSPropertyValueSet::kParseError);

  EXPECT_EQ(style->PropertyCount(), 9U);

  EXPECT_EQ(style->GetPropertyValue(property_id), expected_prop_value);
}

TEST(CSSPropertyParserTest, MaskRepeatFromMaskNone) {
  TestMaskParsing("none", CSSPropertyID::kMaskRepeat, "repeat");
}

TEST(CSSPropertyParserTest, MaskRepeatFromMaskNone2) {
  TestMaskParsing("none, none", CSSPropertyID::kMaskRepeat, "repeat, repeat");
}

TEST(CSSPropertyParserTest, MaskRepeatFromMaskRepeatX) {
  TestMaskParsing("repeat-x", CSSPropertyID::kMaskRepeat, "repeat-x");
}

TEST(CSSPropertyParserTest, MaskRepeatFromMaskRoundSpace) {
  TestMaskParsing("round space", CSSPropertyID::kMaskRepeat, "round space");
}

TEST(CSSPropertyParserTest, MaskClipFromMaskNone) {
  TestMaskParsing("none", CSSPropertyID::kMaskClip, "border-box");
}

TEST(CSSPropertyParserTest, MaskCompositeFromMaskNone) {
  TestMaskParsing("none", CSSPropertyID::kMaskComposite, "add");
}

TEST(CSSPropertyParserTest, MaskModeFromMaskNone) {
  TestMaskParsing("none", CSSPropertyID::kMaskMode, "match-source");
}

TEST(CSSPropertyParserTest, MaskOriginFromMaskNone) {
  TestMaskParsing("none", CSSPropertyID::kMaskOrigin, "border-box");
}

TEST(CSSPropertyParserTest, MaskPositionFromMaskNone) {
  TestMaskParsing("none", CSSPropertyID::kMaskPosition, "0% 0%");
}

TEST(CSSPropertyParserTest, MaskPositionFromMaskNone2) {
  TestMaskParsing("none, none", CSSPropertyID::kMaskPosition, "0% 0%, 0% 0%");
}

TEST(CSSPropertyParserTest, MaskPositionLayered) {
  TestMaskParsing("top right, bottom left", CSSPropertyID::kMaskPosition,
                  "right top, left bottom");
}

TEST(CSSPropertyParserTest, MaskPositionLayered2) {
  TestMaskParsing("top right, none, bottom left", CSSPropertyID::kMaskPosition,
                  "right top, 0% 0%, left bottom");
}

TEST(CSSPropertyParserTest, MaskSizeFromMaskNone) {
  TestMaskParsing("none", CSSPropertyID::kMaskSize, "auto");
}

TEST(CSSPropertyParserTest, MaskFromMaskNoneRepeatY) {
  TestMaskParsing("none repeat-y", CSSPropertyID::kMask, "repeat-y");
}

}  // namespace blink
```