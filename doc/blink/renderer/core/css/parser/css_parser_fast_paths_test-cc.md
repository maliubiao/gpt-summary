Response:
My thinking process to analyze the given C++ test file goes like this:

1. **Understand the Goal:** The request asks for the functionality of the file `css_parser_fast_paths_test.cc`, its relation to web technologies, and insights into potential errors and debugging.

2. **Identify the Core Functionality:** The filename itself, `css_parser_fast_paths_test.cc`, strongly suggests that this file contains tests for a "fast paths" mechanism in the CSS parser. The `#include` directives confirm this, especially  `"third_party/blink/renderer/core/css/parser/css_parser_fast_paths.h"`.

3. **Analyze the Test Structure:** The file uses the Google Test framework (`testing/gtest/include/gtest/gtest.h`). The presence of `TEST(TestSuiteName, TestName)` macros indicates individual test cases. The test suite name `CSSParserFastPathsTest` further reinforces the core functionality being tested.

4. **Break Down Individual Tests:**  I'll go through each `TEST` block to understand what specific aspect of the fast paths is being tested:

    * **`ParseKeyword`:** Tests parsing of single keyword values for CSS properties (e.g., "left" for `float`). It also checks that invalid keywords are not parsed.
    * **`ParseCSSWideKeywords`:** Tests parsing of CSS-wide keywords like `inherit`, `initial`, and `unset`. It also verifies that the fast path doesn't handle shorthand properties.
    * **`ParseRevert` and `ParseRevertLayer`:**  Tests parsing of the `revert` and `revert-layer` keywords, which are related to CSS cascading and layering.
    * **`ParseSimpleLength`:** Tests parsing of simple length values with pixel units (e.g., "234px"). It checks for correct parsing of integers and decimals and identifies cases the fast path *doesn't* handle (like exponential notation).
    * **`VariousNumberOfDecimalsInLength`:** Specifically tests the precision of parsing length values with varying numbers of decimal places, likely focusing on the SIMD optimizations mentioned in the comments.
    * **`ParseTransform` and `ParseComplexTransform`:** Tests parsing of `transform` property values, including `translate`, `translate3d`, `scale3d`, and `matrix3d`. The "ComplexTransform" test highlights the handling of multiple transform functions.
    * **`ParseTransformNotFastPath`:** Explicitly tests cases for `transform` that are *not* handled by the fast path (e.g., `rotateX`).
    * **`ParseInvalidTransform`:** Tests cases with syntactically incorrect `transform` values to ensure they are not parsed.
    * **`ParseColorWithLargeAlpha`, `ParseColorWithNewSyntax`, `ParseColorWithDecimal`, `ParseHSL`, `ParseHSLWithAlpha`, `ParseHSLInvalid`:**  A series of tests dedicated to parsing different color formats (RGBA, RGB, HSL, HSLA) and validating the parsing logic, including handling of different syntaxes, alpha values, and invalid inputs.
    * **`IsValidKeywordPropertyAndValueOverflowClip`:**  Tests a specific utility function that checks if a given keyword value is valid for a particular CSS property.
    * **`InternalColorsOnlyAllowedInUaMode`:** Tests that certain "internal" color keywords are only recognized when parsing user-agent stylesheets (UASheetMode), not in regular HTML or quirks mode.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):**

    * **CSS:** This is the most direct connection. The tests are explicitly about parsing CSS values. I'll provide examples of how these parsed values affect styling in a web page.
    * **HTML:**  CSS is applied to HTML elements. I can explain how CSS rules defined in `<style>` tags or linked stylesheets are parsed, potentially using these fast paths.
    * **JavaScript:** JavaScript can manipulate CSS styles through the DOM. I'll describe scenarios where JavaScript might set or get CSS property values, and how the browser's CSS parser comes into play.

6. **Identify Logical Reasoning and Examples:**

    * **Assumption:** The "fast paths" aim to optimize the parsing of common CSS values.
    * **Input/Output:** For each test, I'll describe the CSS property and the input string being tested and the expected output (a parsed `CSSValue` object or `nullptr`).

7. **Consider User/Programming Errors:**

    * **Typos:** Incorrectly spelled keywords or function names.
    * **Syntax Errors:** Missing parentheses, commas, or incorrect units.
    * **Invalid Values:** Providing values that are out of range or not supported for a specific property.

8. **Trace User Operations to Reach the Code:**  This involves thinking about the browser's rendering pipeline:

    * A user loads a webpage.
    * The browser fetches the HTML, CSS files, and any inline styles.
    * The CSS parser, potentially using these fast paths, parses the CSS rules.
    * The parsed styles are used to create the render tree.
    * The render tree is used to paint the page.

    I'll describe these steps and point out where the `CSSParserFastPaths` code fits in. For debugging, I'll explain how a developer might inspect styles in the browser's developer tools, which could lead to investigating the parsing logic if unexpected styles are applied.

9. **Structure the Answer:** I'll organize the information logically with clear headings and examples for each point. I'll start with a summary, then delve into the details of each test, the relationship to web technologies, error scenarios, and the debugging perspective.

By following these steps, I can systematically analyze the code and provide a comprehensive and informative answer to the user's request. The key is to understand the purpose of the code, analyze its structure, and then connect it to the broader context of web development and browser functionality.
这个文件 `blink/renderer/core/css/parser/css_parser_fast_paths_test.cc` 是 Chromium Blink 引擎中用于测试 **CSS 快速解析路径 (fast paths)** 功能的单元测试文件。

**它的主要功能是：**

1. **测试 `CSSParserFastPaths` 类的功能：**  `CSSParserFastPaths` 类旨在提供一种优化的方式来解析常见的 CSS 属性值，以提高解析性能。这个测试文件验证了该类是否能正确地解析各种 CSS 值，以及在哪些情况下能够使用快速路径，哪些情况下不能使用。

2. **确保快速解析的正确性：** 通过编写各种测试用例，覆盖了 `CSSParserFastPaths` 可以处理的不同 CSS 语法和值类型，确保在优化性能的同时，解析结果的正确性与完整 CSS 解析器保持一致。

**它与 JavaScript, HTML, CSS 的功能关系：**

这个文件直接关联的是 **CSS** 的功能，因为它测试的是 CSS 属性值的解析。

* **CSS:**  该文件测试了如何将 CSS 属性的字符串值（例如 "left"、"234px"、"rgba(0,0,0,1)"）转换为 Blink 内部表示的 `CSSValue` 对象。这些 `CSSValue` 对象随后会被用于布局、渲染等过程，最终影响网页的视觉呈现。

**举例说明：**

* **CSS 关键字：**  `TEST(CSSParserFastPathsTest, ParseKeyword)` 测试了像 `float: left;` 中的 `left` 关键字的解析。它验证了当 `CSSParserFastPaths::MaybeParseValue` 被调用时，对于 `float` 属性和字符串 "left"，它能正确返回一个代表 `CSSValueID::kLeft` 的 `CSSIdentifierValue` 对象。

* **CSS 长度值：** `TEST(CSSParserFastPathsTest, ParseSimpleLength)` 测试了像 `width: 234px;` 中的 `234px` 长度值的解析。它验证了对于 `width` 属性和字符串 "234px"，它能正确返回一个代表 234 像素的 `CSSNumericLiteralValue` 对象。

* **CSS 颜色值：** `TEST(CSSParserFastPathsTest, ParseColorWithNewSyntax)` 测试了像 `background-color: rgba(0 0 0);` 这种新语法的颜色值解析。它验证了对于这样的字符串，`CSSParserFastPaths::ParseColor` 能正确解析为黑色。

* **CSS `transform` 属性：** `TEST(CSSParserFastPathsTest, ParseTransform)` 测试了像 `transform: translate(5.5px, 5px);` 这样的转换函数解析。它验证了对于这样的字符串，能正确解析为一个包含 `Translate` 函数的 `CSSValueList`。

**逻辑推理 (假设输入与输出):**

假设输入是以下 CSS 属性和值：

* **输入属性:** `CSSPropertyID::kMarginLeft`
* **输入字符串:** `"10px"`

**预期输出：**  `CSSParserFastPaths::MaybeParseValue` 应该返回一个指向 `CSSNumericLiteralValue` 对象的指针，该对象表示 10 像素的长度值。通过 `value->CssText()` 应该得到字符串 `"10px"`。通过 `To<CSSNumericLiteralValue>(value)->DoubleValue()` 应该得到浮点数 `10.0`。

**涉及用户或编程常见的使用错误：**

* **拼写错误：** 用户在 CSS 中输入错误的关键字，例如 `floot: left;` 而不是 `float: left;`。`ParseKeyword` 测试中 `value = CSSParserFastPaths::MaybeParseValue(CSSPropertyID::kFloat, "foo", context);` 验证了快速路径在遇到未知关键字时返回 `nullptr`。

* **语法错误：** 用户在 CSS 中输入错误的语法，例如 `width: 234 px;` (缺少单位和值之间的空格) 或 `transform: translate(10px, );` (缺少参数)。  虽然这个测试文件侧重于快速路径，但其目标是与完整的 CSS 解析器行为一致，所以快速路径无法处理的复杂错误最终会由完整的解析器处理。 `ParseInvalidTransform` 测试了 `transform` 属性的一些错误语法，确保快速路径不会错误地解析它们。

* **单位错误：**  对于需要特定单位的属性，用户可能使用了错误的单位。例如，对于 `opacity` 属性使用长度单位，例如 `opacity: 10px;`。虽然这个测试文件没有直接测试单位错误，但它测试了长度单位的正确解析，暗示了对单位的检查。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中打开一个网页。**
2. **浏览器开始解析 HTML 文档。**
3. **在解析 HTML 的过程中，浏览器遇到了 `<style>` 标签或者 `<link>` 标签引用的 CSS 文件。**
4. **浏览器调用 CSS 解析器来解析这些 CSS 代码。**
5. **CSS 解析器在解析 CSS 属性值时，会尝试使用 `CSSParserFastPaths` 进行快速解析。**
6. **如果 CSS 属性值符合快速解析的条件（例如，是常见的关键字、简单的长度值、特定的转换函数或颜色格式），`CSSParserFastPaths::MaybeParseValue` 或 `CSSParserFastPaths::ParseColor` 等函数会被调用。**
7. **如果快速解析成功，会直接返回解析后的 `CSSValue` 对象，加速解析过程。**
8. **如果快速解析失败（例如，遇到了复杂的语法或不常见的属性值），CSS 解析器会退回到更完整的、但可能更慢的解析路径。**

**作为调试线索：**

* **性能问题：** 如果网页加载或渲染性能较差，开发者可能会怀疑 CSS 解析是否是瓶颈之一。他们可以使用浏览器的开发者工具（例如 Chrome DevTools 的 Performance 面板）来分析 CSS 解析的时间。如果发现 CSS 解析耗时较长，可以考虑优化 CSS 规则，使其更容易被快速路径处理。

* **样式未生效或错误：** 如果网页元素的样式没有按照预期显示，开发者会检查 CSS 规则是否正确。他们可以使用开发者工具的 Elements 面板查看元素的计算样式，以及应用的 CSS 规则。如果怀疑是解析问题，他们可以尝试简化 CSS 规则，看看是否能被快速路径处理，从而排除快速路径本身的问题。

* **Blink 引擎开发者调试：**  Blink 引擎的开发者在修改或优化 CSS 解析器时，会运行这些单元测试来确保他们的改动没有引入 bug，并且快速路径仍然能够正确地解析各种 CSS 值。如果某个测试失败，说明他们的改动可能破坏了快速路径的某些功能。他们会查看具体的测试用例和 `CSSParserFastPaths` 的实现，找出问题所在。

总而言之，`css_parser_fast_paths_test.cc` 是确保 Chromium Blink 引擎能够高效且正确地解析常见 CSS 属性值的关键组成部分，它直接影响着网页的渲染性能和视觉呈现。

### 提示词
```
这是目录为blink/renderer/core/css/parser/css_parser_fast_paths_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/parser/css_parser_fast_paths.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/css_color.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"

namespace blink {

TEST(CSSParserFastPathsTest, ParseKeyword) {
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  CSSValue* value = CSSParserFastPaths::MaybeParseValue(CSSPropertyID::kFloat,
                                                        "left", context);
  ASSERT_NE(nullptr, value);
  CSSIdentifierValue* identifier_value = To<CSSIdentifierValue>(value);
  EXPECT_EQ(CSSValueID::kLeft, identifier_value->GetValueID());
  value = CSSParserFastPaths::MaybeParseValue(CSSPropertyID::kFloat, "foo",
                                              context);
  ASSERT_EQ(nullptr, value);
}

TEST(CSSParserFastPathsTest, ParseCSSWideKeywords) {
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  CSSValue* value = CSSParserFastPaths::MaybeParseValue(
      CSSPropertyID::kMarginTop, "inherit", context);
  ASSERT_NE(nullptr, value);
  EXPECT_TRUE(value->IsInheritedValue());
  value = CSSParserFastPaths::MaybeParseValue(CSSPropertyID::kMarginRight,
                                              "InHeriT", context);
  ASSERT_NE(nullptr, value);
  EXPECT_TRUE(value->IsInheritedValue());
  value = CSSParserFastPaths::MaybeParseValue(CSSPropertyID::kMarginBottom,
                                              "initial", context);
  ASSERT_NE(nullptr, value);
  EXPECT_TRUE(value->IsInitialValue());
  value = CSSParserFastPaths::MaybeParseValue(CSSPropertyID::kMarginLeft,
                                              "IniTiaL", context);
  ASSERT_NE(nullptr, value);
  EXPECT_TRUE(value->IsInitialValue());
  value = CSSParserFastPaths::MaybeParseValue(CSSPropertyID::kMarginTop,
                                              "unset", context);
  ASSERT_NE(nullptr, value);
  EXPECT_TRUE(value->IsUnsetValue());
  value = CSSParserFastPaths::MaybeParseValue(CSSPropertyID::kMarginLeft,
                                              "unsEt", context);
  ASSERT_NE(nullptr, value);
  EXPECT_TRUE(value->IsUnsetValue());
  // Fast path doesn't handle short hands.
  value = CSSParserFastPaths::MaybeParseValue(CSSPropertyID::kMargin, "initial",
                                              context);
  ASSERT_EQ(nullptr, value);
}

TEST(CSSParserFastPathsTest, ParseRevert) {
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  // Revert enabled, IsHandledByKeywordFastPath=false
  {
    DCHECK(!CSSParserFastPaths::IsHandledByKeywordFastPath(
        CSSPropertyID::kMarginTop));
    CSSValue* value = CSSParserFastPaths::MaybeParseValue(
        CSSPropertyID::kMarginTop, "revert", context);
    ASSERT_TRUE(value);
    EXPECT_TRUE(value->IsRevertValue());
  }

  // Revert enabled, IsHandledByKeywordFastPath=true
  {
    DCHECK(CSSParserFastPaths::IsHandledByKeywordFastPath(
        CSSPropertyID::kDirection));
    CSSValue* value = CSSParserFastPaths::MaybeParseValue(
        CSSPropertyID::kDirection, "revert", context);
    ASSERT_TRUE(value);
    EXPECT_TRUE(value->IsRevertValue());
  }
}

TEST(CSSParserFastPathsTest, ParseRevertLayer) {
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  // 'revert-layer' enabled, IsHandledByKeywordFastPath=false
  {
    DCHECK(!CSSParserFastPaths::IsHandledByKeywordFastPath(
        CSSPropertyID::kMarginTop));
    CSSValue* value = CSSParserFastPaths::MaybeParseValue(
        CSSPropertyID::kMarginTop, "revert-layer", context);
    ASSERT_TRUE(value);
    EXPECT_TRUE(value->IsRevertLayerValue());
  }

  // 'revert-layer' enabled, IsHandledByKeywordFastPath=true
  {
    DCHECK(CSSParserFastPaths::IsHandledByKeywordFastPath(
        CSSPropertyID::kDirection));
    CSSValue* value = CSSParserFastPaths::MaybeParseValue(
        CSSPropertyID::kDirection, "revert-layer", context);
    ASSERT_TRUE(value);
    EXPECT_TRUE(value->IsRevertLayerValue());
  }
}

TEST(CSSParserFastPathsTest, ParseSimpleLength) {
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  CSSValue* value = CSSParserFastPaths::MaybeParseValue(CSSPropertyID::kWidth,
                                                        "234px", context);
  ASSERT_NE(nullptr, value);
  EXPECT_FALSE(value->IsValueList());
  EXPECT_EQ("234px", value->CssText());

  value = CSSParserFastPaths::MaybeParseValue(CSSPropertyID::kWidth,
                                              "234.567px", context);
  ASSERT_NE(nullptr, value);
  EXPECT_FALSE(value->IsValueList());
  EXPECT_EQ("234.567px", value->CssText());

  value = CSSParserFastPaths::MaybeParseValue(CSSPropertyID::kWidth, ".567px",
                                              context);
  ASSERT_NE(nullptr, value);
  EXPECT_FALSE(value->IsValueList());
  EXPECT_EQ("0.567px", value->CssText());

  value = CSSParserFastPaths::MaybeParseValue(CSSPropertyID::kWidth, "234.px",
                                              context);
  EXPECT_EQ(nullptr, value);

  value = CSSParserFastPaths::MaybeParseValue(CSSPropertyID::kWidth, "234.e2px",
                                              context);
  EXPECT_EQ(nullptr, value);

  value =
      CSSParserFastPaths::MaybeParseValue(CSSPropertyID::kWidth, ".", context);
  EXPECT_EQ(nullptr, value);

  // This is legal, but we don't support it in the fast path.
  value = CSSParserFastPaths::MaybeParseValue(CSSPropertyID::kWidth, "234e2px",
                                              context);
  EXPECT_EQ(nullptr, value);
}

// Mostly to stress-test the SIMD paths.
TEST(CSSParserFastPathsTest, VariousNumberOfDecimalsInLength) {
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  const std::pair<std::string, double> kTestCases[] = {
      {"0.1px", 0.1},
      {"0.12px", 0.12},
      {"0.123px", 0.123},
      {"0.1234px", 0.1234},
      {"0.12345px", 0.12345},
      {"0.123456px", 0.123456},
      {"0.1234567px", 0.1234567},
      {"0.12345678px", 0.1234567},   // NOTE: Max. seven digits.
      {"0.123456789px", 0.1234567},  // NOTE: Max. seven digits.
  };
  for (const auto& [str, expected_val] : kTestCases) {
    SCOPED_TRACE(str);
    CSSValue* value = CSSParserFastPaths::MaybeParseValue(CSSPropertyID::kWidth,
                                                          str.c_str(), context);
    ASSERT_NE(nullptr, value);
    EXPECT_FALSE(value->IsValueList());
    EXPECT_DOUBLE_EQ(expected_val,
                     To<CSSNumericLiteralValue>(value)->DoubleValue());
  }
}

TEST(CSSParserFastPathsTest, ParseTransform) {
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  CSSValue* value = CSSParserFastPaths::MaybeParseValue(
      CSSPropertyID::kTransform, "translate(5.5px, 5px)", context);
  ASSERT_NE(nullptr, value);
  ASSERT_TRUE(value->IsValueList());
  ASSERT_EQ("translate(5.5px, 5px)", value->CssText());

  value = CSSParserFastPaths::MaybeParseValue(
      CSSPropertyID::kTransform, "translate3d(5px, 5px, 10.1px)", context);
  ASSERT_NE(nullptr, value);
  ASSERT_TRUE(value->IsValueList());
  ASSERT_EQ("translate3d(5px, 5px, 10.1px)", value->CssText());
}

TEST(CSSParserFastPathsTest, ParseComplexTransform) {
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  // Random whitespace is on purpose.
  static const char* kComplexTransform =
      "translateX(5px) "
      "translateZ(20.5px)   "
      "translateY(10px) "
      "scale3d(0.5, 1, 0.7)   "
      "matrix3d(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)   ";
  static const char* kComplexTransformNormalized =
      "translateX(5px) "
      "translateZ(20.5px) "
      "translateY(10px) "
      "scale3d(0.5, 1, 0.7) "
      "matrix3d(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)";
  CSSValue* value = CSSParserFastPaths::MaybeParseValue(
      CSSPropertyID::kTransform, kComplexTransform, context);
  ASSERT_NE(nullptr, value);
  ASSERT_TRUE(value->IsValueList());
  ASSERT_EQ(kComplexTransformNormalized, value->CssText());
}

TEST(CSSParserFastPathsTest, ParseTransformNotFastPath) {
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  CSSValue* value = CSSParserFastPaths::MaybeParseValue(
      CSSPropertyID::kTransform, "rotateX(1deg)", context);
  ASSERT_EQ(nullptr, value);
  value = CSSParserFastPaths::MaybeParseValue(
      CSSPropertyID::kTransform, "translateZ(1px) rotateX(1deg)", context);
  ASSERT_EQ(nullptr, value);
}

TEST(CSSParserFastPathsTest, ParseInvalidTransform) {
  auto* context = MakeGarbageCollected<CSSParserContext>(
      kHTMLStandardMode, SecureContextMode::kInsecureContext);
  CSSValue* value = CSSParserFastPaths::MaybeParseValue(
      CSSPropertyID::kTransform, "rotateX(1deg", context);
  ASSERT_EQ(nullptr, value);
  value = CSSParserFastPaths::MaybeParseValue(
      CSSPropertyID::kTransform, "translateZ(1px) (1px, 1px) rotateX(1deg",
      context);
  ASSERT_EQ(nullptr, value);
}

TEST(CSSParserFastPathsTest, ParseColorWithLargeAlpha) {
  Color color;
  EXPECT_EQ(ParseColorResult::kColor,
            CSSParserFastPaths::ParseColor("rgba(0,0,0,1893205797.13)",
                                           kHTMLStandardMode, color));
  EXPECT_EQ(Color::kBlack, color);
}

TEST(CSSParserFastPathsTest, ParseColorWithNewSyntax) {
  Color color;
  EXPECT_EQ(
      ParseColorResult::kColor,
      CSSParserFastPaths::ParseColor("rgba(0 0 0)", kHTMLStandardMode, color));
  EXPECT_EQ(Color::kBlack, color);

  EXPECT_EQ(ParseColorResult::kColor,
            CSSParserFastPaths::ParseColor("rgba(0 0 0 / 1)", kHTMLStandardMode,
                                           color));
  EXPECT_EQ(Color::kBlack, color);

  EXPECT_EQ(ParseColorResult::kColor,
            CSSParserFastPaths::ParseColor("rgba(0, 0, 0, 1)",
                                           kHTMLStandardMode, color));
  EXPECT_EQ(Color::kBlack, color);

  EXPECT_EQ(ParseColorResult::kFailure,
            CSSParserFastPaths::ParseColor("rgba(0 0 0 0)", kHTMLStandardMode,
                                           color));

  EXPECT_EQ(ParseColorResult::kFailure,
            CSSParserFastPaths::ParseColor("rgba(0, 0 0 1)", kHTMLStandardMode,
                                           color));

  EXPECT_EQ(ParseColorResult::kFailure,
            CSSParserFastPaths::ParseColor("rgba(0, 0, 0 / 1)",
                                           kHTMLStandardMode, color));

  EXPECT_EQ(ParseColorResult::kFailure,
            CSSParserFastPaths::ParseColor("rgba(0 0 0, 1)", kHTMLStandardMode,
                                           color));
}

TEST(CSSParserFastPathsTest, ParseColorWithDecimal) {
  Color color;
  EXPECT_EQ(ParseColorResult::kColor,
            CSSParserFastPaths::ParseColor("rgba(0.0, 0.0, 0.0, 1.0)",
                                           kHTMLStandardMode, color));
  EXPECT_EQ(Color::kBlack, color);

  EXPECT_EQ(ParseColorResult::kColor,
            CSSParserFastPaths::ParseColor("rgb(0.0, 0.0, 0.0)",
                                           kHTMLStandardMode, color));
  EXPECT_EQ(Color::kBlack, color);

  EXPECT_EQ(ParseColorResult::kColor,
            CSSParserFastPaths::ParseColor("rgb(0.0 , 0.0,0.0)",
                                           kHTMLStandardMode, color));
  EXPECT_EQ(Color::kBlack, color);

  EXPECT_EQ(ParseColorResult::kColor,
            CSSParserFastPaths::ParseColor("rgb(254.5, 254.5, 254.5)",
                                           kHTMLStandardMode, color));
  EXPECT_EQ(Color::kWhite, color);
}

TEST(CSSParserFastPathsTest, ParseHSL) {
  Color color;
  EXPECT_EQ(ParseColorResult::kColor,
            CSSParserFastPaths::ParseColor("hsl(90deg, 50%, 25%)",
                                           kHTMLStandardMode, color));
  EXPECT_EQ("rgb(64, 96, 32)", color.SerializeAsCSSColor());

  // Implicit “deg” angle.
  EXPECT_EQ(ParseColorResult::kColor,
            CSSParserFastPaths::ParseColor("hsl(180, 50%, 50%)",
                                           kHTMLStandardMode, color));
  EXPECT_EQ("rgb(64, 191, 191)", color.SerializeAsCSSColor());

  // turn.
  EXPECT_EQ(ParseColorResult::kColor,
            CSSParserFastPaths::ParseColor("hsl(0.25turn, 25%, 50%)",
                                           kHTMLStandardMode, color));
  EXPECT_EQ("rgb(128, 159, 96)", color.SerializeAsCSSColor());

  // rad.
  EXPECT_EQ(ParseColorResult::kColor,
            CSSParserFastPaths::ParseColor("hsl(1.0rad, 50%, 50%)",
                                           kHTMLStandardMode, color));
  EXPECT_EQ("rgb(191, 186, 64)", color.SerializeAsCSSColor());

  // Wraparound.
  EXPECT_EQ(ParseColorResult::kColor,
            CSSParserFastPaths::ParseColor("hsl(450deg, 50%, 50%)",
                                           kHTMLStandardMode, color));
  EXPECT_EQ("rgb(128, 191, 64)", color.SerializeAsCSSColor());

  // Lots of wraparound.
  EXPECT_EQ(ParseColorResult::kColor,
            CSSParserFastPaths::ParseColor("hsl(4050deg, 50%, 50%)",
                                           kHTMLStandardMode, color));
  EXPECT_EQ("rgb(128, 191, 64)", color.SerializeAsCSSColor());

  // Negative wraparound.
  EXPECT_EQ(ParseColorResult::kColor,
            CSSParserFastPaths::ParseColor("hsl(-270deg, 50%, 50%)",
                                           kHTMLStandardMode, color));
  EXPECT_EQ("rgb(128, 191, 64)", color.SerializeAsCSSColor());

  // Saturation clamping.
  EXPECT_EQ(ParseColorResult::kColor,
            CSSParserFastPaths::ParseColor("hsl(45deg, 150%, 50%)",
                                           kHTMLStandardMode, color));
  EXPECT_EQ("rgb(255, 191, 0)", color.SerializeAsCSSColor());

  // Lightness clamping to negative.
  EXPECT_EQ(ParseColorResult::kColor,
            CSSParserFastPaths::ParseColor("hsl(45deg, 150%, -1000%)",
                                           kHTMLStandardMode, color));
  EXPECT_EQ("rgb(0, 0, 0)", color.SerializeAsCSSColor());

  // Writing hsla() without alpha.
  EXPECT_EQ(ParseColorResult::kColor,
            CSSParserFastPaths::ParseColor("hsla(45deg, 150%, 50%)",
                                           kHTMLStandardMode, color));
  EXPECT_EQ("rgb(255, 191, 0)", color.SerializeAsCSSColor());

  // Stray period at the end
  EXPECT_NE(ParseColorResult::kColor,
            CSSParserFastPaths::ParseColor("hsl(0.turn, 25%, 50%)",
                                           kHTMLStandardMode, color));
}

TEST(CSSParserFastPathsTest, ParseHSLWithAlpha) {
  // With alpha, using hsl().
  Color color;
  EXPECT_EQ(ParseColorResult::kColor,
            CSSParserFastPaths::ParseColor("hsl(30 , 1%,75%, 0.5)",
                                           kHTMLStandardMode, color));
  EXPECT_EQ("rgba(192, 191, 191, 0.5)", color.SerializeAsCSSColor());

  // With alpha, using hsla().
  EXPECT_EQ(ParseColorResult::kColor,
            CSSParserFastPaths::ParseColor("hsla(30 , 1%,75%, 0.5)",
                                           kHTMLStandardMode, color));
  EXPECT_EQ("rgba(192, 191, 191, 0.5)", color.SerializeAsCSSColor());

  // With alpha, using space-separated syntax.
  EXPECT_EQ(ParseColorResult::kColor,
            CSSParserFastPaths::ParseColor("hsla(30 1% 75% / 0.1)",
                                           kHTMLStandardMode, color));
  EXPECT_EQ("rgba(192, 191, 191, 0.1)", color.SerializeAsCSSColor());

  // Clamp alpha.
  EXPECT_EQ(ParseColorResult::kColor,
            CSSParserFastPaths::ParseColor("hsla(30 1% 75% / 1.2)",
                                           kHTMLStandardMode, color));
  EXPECT_EQ("rgb(192, 191, 191)", color.SerializeAsCSSColor());
}

TEST(CSSParserFastPathsTest, ParseHSLInvalid) {
  // Invalid unit.
  Color color;
  EXPECT_EQ(ParseColorResult::kFailure,
            CSSParserFastPaths::ParseColor("hsl(20dag, 50%, 20%)",
                                           kHTMLStandardMode, color));

  // Mix of new and old space syntax.
  EXPECT_EQ(ParseColorResult::kFailure,
            CSSParserFastPaths::ParseColor("hsl(0.2, 50%, 20% 0.3)",
                                           kHTMLStandardMode, color));
  EXPECT_EQ(ParseColorResult::kFailure,
            CSSParserFastPaths::ParseColor("hsl(0.2, 50%, 20% / 0.3)",
                                           kHTMLStandardMode, color));
  EXPECT_EQ(ParseColorResult::kFailure,
            CSSParserFastPaths::ParseColor("hsl(0.2 50% 20%, 0.3)",
                                           kHTMLStandardMode, color));

  // Junk after percentage.
  EXPECT_EQ(ParseColorResult::kFailure,
            CSSParserFastPaths::ParseColor("hsl(0.2, 50% foo, 20% 0.3)",
                                           kHTMLStandardMode, color));

  // Stopping right before an expected %.
  EXPECT_EQ(
      ParseColorResult::kFailure,
      CSSParserFastPaths::ParseColor("hsl(9,0.6", kHTMLStandardMode, color));
}

TEST(CSSParserFastPathsTest, IsValidKeywordPropertyAndValueOverflowClip) {
  EXPECT_TRUE(CSSParserFastPaths::IsValidKeywordPropertyAndValue(
      CSSPropertyID::kOverflowX, CSSValueID::kClip,
      CSSParserMode::kHTMLStandardMode));
}

TEST(CSSParserFastPathsTest, InternalColorsOnlyAllowedInUaMode) {
  Color color;

  EXPECT_EQ(ParseColorResult::kKeyword,
            CSSParserFastPaths::ParseColor("blue", kHTMLStandardMode, color));
  EXPECT_EQ(ParseColorResult::kKeyword,
            CSSParserFastPaths::ParseColor("blue", kHTMLQuirksMode, color));
  EXPECT_EQ(ParseColorResult::kKeyword,
            CSSParserFastPaths::ParseColor("blue", kUASheetMode, color));

  EXPECT_EQ(ParseColorResult::kFailure,
            CSSParserFastPaths::ParseColor("-internal-spelling-error-color",
                                           kHTMLStandardMode, color));
  EXPECT_EQ(ParseColorResult::kFailure,
            CSSParserFastPaths::ParseColor("-internal-spelling-error-color",
                                           kHTMLQuirksMode, color));
  EXPECT_EQ(ParseColorResult::kKeyword,
            CSSParserFastPaths::ParseColor("-internal-spelling-error-color",
                                           kUASheetMode, color));

  EXPECT_EQ(ParseColorResult::kFailure,
            CSSParserFastPaths::ParseColor("-internal-grammar-error-color",
                                           kHTMLStandardMode, color));
  EXPECT_EQ(ParseColorResult::kFailure,
            CSSParserFastPaths::ParseColor("-internal-grammar-error-color",
                                           kHTMLQuirksMode, color));
  EXPECT_EQ(ParseColorResult::kKeyword,
            CSSParserFastPaths::ParseColor("-internal-grammar-error-color",
                                           kUASheetMode, color));

  EXPECT_EQ(ParseColorResult::kFailure,
            CSSParserFastPaths::ParseColor("-internal-search-color",
                                           kHTMLStandardMode, color));
  EXPECT_EQ(ParseColorResult::kFailure,
            CSSParserFastPaths::ParseColor("-internal-search-color",
                                           kHTMLQuirksMode, color));
  EXPECT_EQ(ParseColorResult::kKeyword,
            CSSParserFastPaths::ParseColor("-internal-search-color",
                                           kUASheetMode, color));

  EXPECT_EQ(ParseColorResult::kFailure,
            CSSParserFastPaths::ParseColor("-internal-search-text-color",
                                           kHTMLStandardMode, color));
  EXPECT_EQ(ParseColorResult::kFailure,
            CSSParserFastPaths::ParseColor("-internal-search-text-color",
                                           kHTMLQuirksMode, color));
  EXPECT_EQ(ParseColorResult::kKeyword,
            CSSParserFastPaths::ParseColor("-internal-search-text-color",
                                           kUASheetMode, color));

  EXPECT_EQ(ParseColorResult::kFailure,
            CSSParserFastPaths::ParseColor("-internal-current-search-color",
                                           kHTMLStandardMode, color));
  EXPECT_EQ(ParseColorResult::kFailure,
            CSSParserFastPaths::ParseColor("-internal-current-search-color",
                                           kHTMLQuirksMode, color));
  EXPECT_EQ(ParseColorResult::kKeyword,
            CSSParserFastPaths::ParseColor("-internal-current-search-color",
                                           kUASheetMode, color));

  EXPECT_EQ(
      ParseColorResult::kFailure,
      CSSParserFastPaths::ParseColor("-internal-current-search-text-color",
                                     kHTMLStandardMode, color));
  EXPECT_EQ(ParseColorResult::kFailure,
            CSSParserFastPaths::ParseColor(
                "-internal-current-search-text-color", kHTMLQuirksMode, color));
  EXPECT_EQ(ParseColorResult::kKeyword,
            CSSParserFastPaths::ParseColor(
                "-internal-current-search-text-color", kUASheetMode, color));
}

}  // namespace blink
```