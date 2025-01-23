Response:
Let's break down the thought process to arrive at the comprehensive explanation of the `css_parsing_utils_test.cc` file.

1. **Understand the Goal:** The request asks for an explanation of the file's purpose, its relation to web technologies, examples, logic, common errors, and debugging context.

2. **Initial Scan and Keyword Identification:**  Read through the code, looking for key terms and patterns. I see:
    * `TEST` (from `gtest`): This immediately tells me it's a test file.
    * `CSSParsingUtilsTest`:  The main test suite name suggests it's testing utility functions for CSS parsing.
    * Function names like `ConsumeAngle`, `AtIdent`, `ConsumeIfDelimiter`, `ConsumeColor`:  These point to specific CSS parsing operations being tested.
    * Includes like `<style>`, `shape-outside`: These connect to CSS properties.
    * Mentions of `Document`, `documentElement`, `setInnerHTML`:  These are DOM manipulation concepts, linking to HTML structure.
    * `CSSParserTokenStream`, `CSSParserContext`, `CSSValueID`: These are specific classes/enums within the Blink rendering engine's CSS parsing infrastructure.
    * `WebFeature::kCSSBasicShape`:  This links to a specific CSS feature and its tracking.

3. **High-Level Purpose Identification:** Based on the keywords, the primary function of this file is to **test the correctness of CSS parsing utility functions** within the Blink rendering engine.

4. **Categorize Test Cases:**  Group the individual tests by the utility functions they are testing:
    * Tests for `ConsumeAngle`:  `ConsumeAngles`
    * Tests for `AtIdent`: `AtIdent`, `ConsumeIfIdent`
    * Tests for `AtDelimiter`: `AtDelimiter`, `ConsumeIfDelimiter`
    * Tests for `ConsumeAnyValue`: `ConsumeAnyValue_Stream`
    * Tests for `IsDashedIdent`: `DashedIdent`
    * Tests for `ConsumeColor`: `ConsumeAbsoluteColor`, `InternalColorsOnlyAllowedInUaMode`, `ConsumeColorRangePreservation`
    * Tests for `ConsumePositionTryFallbacks`: `InternalPositionTryFallbacksInUAMode`, `ConsumePositionTryFallbacksInUAMode`
    * Tests for general wide keywords: `Revert`
    * Tests for feature usage counting: `BasicShapeUseCount`

5. **Explain Each Test Category:**  For each category, describe:
    * The specific utility function being tested.
    * What that function does in the context of CSS parsing.
    * Examples from the test code.

6. **Connect to Web Technologies:**  Explicitly link the tested functions to JavaScript, HTML, and CSS:
    * **CSS:**  The core subject matter. Provide examples of CSS syntax that these utilities would process (e.g., angle values, identifiers, delimiters, color names).
    * **HTML:** Explain how CSS is applied to HTML elements (via `<style>` tags or inline styles). The `BasicShapeUseCount` test provides a direct example.
    * **JavaScript:** Explain how JavaScript can manipulate CSS styles (using the CSSOM), and how the parsing utilities are essential for this interaction.

7. **Illustrate Logic and Reasoning:**  For tests that involve comparisons or specific input/output expectations, provide clear examples:
    * **`ConsumeAngle` with min/max:** Show how the utility clips values outside the allowed range.
    * **`AtIdent` and `ConsumeIfIdent`:**  Demonstrate the difference between checking for an identifier without consuming it and checking and consuming it.
    * **`ConsumeColor` and parser modes:** Explain how the parsing behavior differs based on the `CSSParserMode` (e.g., allowing internal colors only in UA sheets).

8. **Identify Common Usage Errors:** Think about how developers might misuse CSS or the underlying parsing mechanisms:
    * Incorrect CSS syntax (e.g., missing units for angles).
    * Expecting internal CSS features to work everywhere.
    * Misunderstanding the behavior of functions like `ConsumeIfIdent`.

9. **Construct the Debugging Scenario:** Create a plausible sequence of user actions and developer debugging steps that would lead to examining this test file:
    * Start with a user encountering a visual issue related to CSS.
    * Trace the developer's investigation through browser developer tools, CSS property inspection, and potentially deeper into the rendering engine's source code. Emphasize the role of this test file in understanding the expected behavior of the CSS parsing utilities.

10. **Refine and Organize:**  Structure the information logically using headings and bullet points for clarity. Ensure the language is precise and avoids jargon where possible, while still being technically accurate. Double-check the code snippets and explanations for correctness. Ensure a smooth flow from the general purpose of the file to specific details and examples. For instance, start with the general function and then drill down into specific test cases.

**Self-Correction/Refinement during the process:**

* **Initial Thought:** "This is just testing CSS parsing."  **Correction:**  Need to be more specific – *which* aspects of CSS parsing?  Focus on the individual utility functions.
* **Overly Technical:**  Initially used too much internal Blink terminology. **Correction:**  Explain concepts in a way that's understandable even without deep knowledge of the Blink codebase. Relate to broader web development concepts.
* **Lack of Concrete Examples:** Simply stating a function's purpose isn't enough. **Correction:**  Include code snippets and illustrative examples for each function.
* **Missing the "Why":**  Didn't initially emphasize *why* these tests are important. **Correction:** Highlight the role of these tests in ensuring correct CSS rendering and preventing bugs.
* **Debugging Scenario Too Vague:**  The initial debugging scenario was generic. **Correction:**  Make it more concrete and step-by-step, showing the connection to the test file.

By following these steps and iterating on the explanations, I could arrive at the comprehensive and informative answer provided earlier.
这个文件 `css_parsing_utils_test.cc` 是 Chromium Blink 引擎中用于测试 **CSS 解析实用工具函数** 的单元测试文件。它主要测试了 `blink/renderer/core/css/properties/css_parsing_utils.h` 中定义的一些辅助 CSS 解析的函数。

**功能列举:**

这个文件主要用于测试以下方面的功能：

1. **角度值的解析和消费 (`ConsumeAngle`)**:
   - 测试能否正确解析不同格式的角度值 (例如 `10deg`, `-3.40282e+38deg`)。
   - 测试角度值的范围限制 (最小值和最大值)。
   - 测试包含 `calc()` 函数的角度值。
   - **与 CSS 的关系:**  CSS 中很多属性会用到角度值，例如 `transform: rotate(45deg);`。这个测试确保了 Blink 能够正确理解和处理这些角度值。
   - **假设输入与输出:**
     - **输入:** 字符串 `"90deg"`
     - **输出:** `90.0` (作为双精度浮点数)
     - **输入:** 字符串 `"calc(10deg + 20deg)"`
     - **输出:** `30.0`
     - **输入:** 字符串 `"calc(infinity * 1deg)"`
     - **输出:** 一个表示最大角度值的双精度浮点数。

2. **检查当前 token 是否为特定的标识符 (`AtIdent`)**:
   - 测试在 token 流中，当前 token 是否匹配给定的标识符字符串。
   - **与 CSS 的关系:** CSS 中大量使用标识符，例如属性名 (`color`)、关键字 (`auto`)、自定义属性名 (`--my-variable`) 等。
   - **假设输入与输出:**
     - **输入:** token 流指向 "foo"，目标标识符 "foo"
     - **输出:** `true`
     - **输入:** token 流指向 "bar"，目标标识符 "foo"
     - **输出:** `false`

3. **如果当前 token 是特定的标识符则消费它 (`ConsumeIfIdent`)**:
   - 测试如果当前 token 匹配给定的标识符，则消费掉该 token，否则不消费。
   - **与 CSS 的关系:** 在解析 CSS 规则时，需要根据不同的标识符来确定接下来的解析逻辑。
   - **假设输入与输出:**
     - **输入:** token 流指向 "foo"，目标标识符 "foo"
     - **操作:** 消费 "foo" token
     - **输出:** `true` (表示已消费)
     - **输入:** token 流指向 "bar"，目标标识符 "foo"
     - **操作:** 不消费 "bar" token
     - **输出:** `false`

4. **检查当前 token 是否为特定的分隔符 (`AtDelimiter`)**:
   - 测试在 token 流中，当前 token 是否匹配给定的分隔符字符。
   - **与 CSS 的关系:** CSS 中使用各种分隔符，例如逗号 (`,`)、冒号 (`:`)、分号 (`;`) 等。
   - **假设输入与输出:**
     - **输入:** token 流指向 ","，目标分隔符 ','
     - **输出:** `true`
     - **输入:** token 流指向 "foo"，目标分隔符 ','
     - **输出:** `false`

5. **如果当前 token 是特定的分隔符则消费它 (`ConsumeIfDelimiter`)**:
   - 测试如果当前 token 匹配给定的分隔符，则消费掉该 token，否则不消费。
   - **与 CSS 的关系:** 解析 CSS 列表值或其他需要分隔符的结构时会用到。
   - **假设输入与输出:**
     - **输入:** token 流指向 ","，目标分隔符 ','
     - **操作:** 消费 "," token
     - **输出:** `true`
     - **输入:** token 流指向 "foo"，目标分隔符 ','
     - **操作:** 不消费 "foo" token
     - **输出:** `false`

6. **消费任意值 (`ConsumeAnyValue`)**:
   - 测试消费任意有效的 CSS 值，直到遇到不属于该值的 token。
   - **与 CSS 的关系:** 用于处理一些可以包含各种值的 CSS 属性。
   - **假设输入与输出:**
     - **输入:** token 流 `"1px solid blue"`
     - **操作:** 消费 "1px solid blue"
     - **输出:** 消费后的 token 流状态。
     - **输入:** token 流 `"rgb(1, 2, 3) abc"`
     - **操作:** 消费 "rgb(1, 2, 3)"
     - **输出:** 剩余 token 流 " abc"

7. **判断是否为双划线的标识符 (`IsDashedIdent`)**:
   - 测试判断一个标识符是否以双划线 (`--`) 开头，常用于 CSS 自定义属性。
   - **与 CSS 的关系:** 用于识别 CSS 自定义属性。
   - **假设输入与输出:**
     - **输入:** token 流指向 "--my-variable"
     - **输出:** `true`
     - **输入:** token 流指向 "my-variable"
     - **输出:** `false`

8. **消费绝对颜色值 (`ConsumeAbsoluteColor`)**:
   - 测试消费绝对颜色值，排除了一些系统颜色关键字 (例如 `Canvas`, `HighlightText`) 和 `currentcolor`。
   - **与 CSS 的关系:** 验证对特定颜色值的解析是否符合预期。
   - **假设输入与输出:**
     - **输入:** token 流指向 "blue"
     - **输出:** 一个表示蓝色值的 `CSSIdentifierValue` 对象。
     - **输入:** token 流指向 "Canvas"
     - **输出:** `nullptr` (因为 `Canvas` 不是绝对颜色)

9. **内部颜色只允许在 UA 模式下使用 (`InternalColorsOnlyAllowedInUaMode`)**:
   - 测试只有在 User-Agent (UA) 样式表模式下才能解析和使用以 `-internal-` 开头的内部颜色关键字。
   - **与 CSS 的关系:** 确保内部颜色不会被普通的网页 CSS 使用。
   - **假设输入与输出:**
     - **输入:** token 流指向 "-internal-spelling-error-color"，解析模式为 `kUASheetMode`
     - **输出:** 一个表示拼写错误颜色的 `CSSIdentifierValue` 对象。
     - **输入:** token 流指向 "-internal-spelling-error-color"，解析模式为 `kHTMLStandardMode`
     - **输出:** `nullptr`

10. **消费颜色值时保留 token 流状态 (`ConsumeColorRangePreservation`)**:
    - 测试当消费颜色值失败时，`CSSParserTokenStream` 的状态是否被正确保留。
    - **与 CSS 的关系:** 确保解析失败不会影响后续的解析。
    - **假设输入与输出:**
        - **输入:** token 流 `"color-mix(42deg)"`
        - **操作:** 尝试消费颜色值，但失败
        - **输出:** `stream.RemainingText()` 仍然是 `"color-mix(42deg)"`

11. **内部位置值在 UA 模式下的尝试回退 (`InternalPositionTryFallbacksInUAMode`)**:
    - 测试在 UA 模式下，允许使用以 `-internal-` 开头的位置值作为回退。
    - **与 CSS 的关系:** 用于处理一些浏览器的内部布局需求。
    - **假设输入与输出:**
        - **输入:** token 流指向 "-internal-foo"，解析模式为 `kUASheetMode`
        - **输出:** 返回一个非空的 `CSSValue` 对象。
        - **输入:** token 流指向 "-internal-foo"，解析模式为 `kHTMLStandardMode`
        - **输出:** 返回 `nullptr`。

12. **消费位置回退值 (`ConsumePositionTryFallbacksInUAMode`)**:
    - 测试消费由多个位置关键字组成的回退值。
    - **与 CSS 的关系:** 用于定义元素在容器内的位置。

13. **`revert` 关键字测试 (`Revert`)**:
    - 测试 `revert` 关键字是否被正确识别为 CSS 的全局关键字。
    - **与 CSS 的关系:** `revert` 关键字用于回滚级联层叠的值。

14. **基本图形的使用计数 (`BasicShapeUseCount`)**:
    - 测试 `shape-outside` 属性是否被正确计数，用于跟踪 CSS 特性的使用情况。
    - **与 CSS 的关系:** `shape-outside` 属性允许定义元素内容可以环绕的非矩形区域。
    - **用户操作与调试线索:** 用户在 HTML 中使用了 `shape-outside: circle();` 这样的 CSS 声明，Blink 引擎在解析和应用样式时会调用相关的解析函数，这个测试就是为了验证这个过程是否触发了相应的计数器。

**与 JavaScript, HTML, CSS 的关系举例:**

* **HTML:**  `BasicShapeUseCount` 测试中，通过 JavaScript 代码 `document.documentElement()->setInnerHTML("<style>span { shape-outside: circle(); }</style>");`  动态地将包含 CSS 规则的 `<style>` 标签添加到 HTML 文档中。这模拟了用户在 HTML 中编写 CSS 的场景。
* **CSS:**  所有的测试都直接或间接地与 CSS 的语法和解析有关。例如，`ConsumeAngleValue("10deg")` 测试了对 CSS 角度值的解析，这直接关联到 CSS 属性中使用的角度单位。
* **JavaScript:** 虽然这个测试文件是用 C++ 编写的，但它测试的功能是 Blink 引擎解析 CSS 的一部分，而 JavaScript 可以通过 DOM API (如 `element.style.property = value`) 来设置元素的 CSS 样式。当 JavaScript 设置了包含需要特殊解析的 CSS 值时，Blink 引擎内部会调用这些 `css_parsing_utils` 中的函数进行解析。例如，如果 JavaScript 设置了 `element.style.transform = 'rotate(45deg)'`，Blink 就会使用类似 `ConsumeAngle` 的函数来解析 `45deg`。

**用户或编程常见的使用错误举例:**

1. **角度单位错误:** 用户在 CSS 中写了 `transform: rotate(45);` (缺少单位)。`ConsumeAngle` 函数在解析时会返回空或者报错，因为 CSS 规范要求角度值必须有单位。
2. **在不支持的上下文中使用内部颜色:** 开发者可能会尝试在普通的网页 CSS 中使用 `-internal-spelling-error-color`，期望改变拼写错误的颜色。但由于 `InternalColorsOnlyAllowedInUaMode` 的测试存在，Blink 引擎会在非 UA 模式下拒绝解析这个颜色值，导致样式不生效。
3. **`ConsumeIfIdent` 的误用:** 开发者可能错误地认为 `ConsumeIfIdent` 只是检查标识符是否存在，而没有意识到它还会消费掉 token。如果在判断后没有正确处理 token 流的位置，可能会导致后续解析错误。例如：
   ```c++
   CSSParserTokenStream stream("foo bar");
   if (ConsumeIfIdent(stream, "foo")) {
     // 开发者可能以为 stream 还指向 "foo"，但实际上已经指向 "bar"
     if (AtIdent(stream.Peek(), "foo")) { // 这会是 false
       // ...
     }
   }
   ```

**用户操作如何一步步的到达这里 (作为调试线索):**

假设用户在网页上遇到了一个与 CSS `shape-outside` 属性相关的渲染问题，例如环绕效果不正确。开发者进行调试的步骤可能如下：

1. **用户报告或开发者发现:** 用户在使用网站时发现某个元素的环绕效果不符合预期。
2. **检查 CSS:** 开发者通过浏览器开发者工具检查该元素的 CSS 样式，确认 `shape-outside` 属性的值。
3. **验证 CSS 语法:** 开发者可能会怀疑 CSS 语法的正确性，查看 MDN 或 CSS 规范，确认 `shape-outside: circle();` 的语法是正确的。
4. **浏览器兼容性:** 开发者可能会检查浏览器兼容性，确认用户使用的浏览器版本支持 `shape-outside`。
5. **Blink 渲染引擎:** 如果问题依然存在，并且涉及到复杂的图形计算，开发者可能会怀疑是浏览器渲染引擎 (Blink) 在解析或应用 `shape-outside` 属性时出现了问题。
6. **查找相关代码:** 开发者可能会在 Blink 的源代码中搜索 `shape-outside` 相关的代码，最终可能会找到 `blink/renderer/core/css/properties/css_parsing_utils.cc` 和 `css_parsing_utils_test.cc`。
7. **查看测试用例:** 开发者会查看 `css_parsing_utils_test.cc` 中的 `BasicShapeUseCount` 测试用例，了解 Blink 引擎是如何测试和处理 `shape-outside` 属性的。
8. **单步调试或日志:**  如果需要更深入的调试，开发者可能会在 Blink 引擎的源代码中设置断点或添加日志，跟踪 `shape-outside` 属性值的解析过程，例如查看 `ConsumeBasicShape` 函数的执行情况，该函数可能会调用 `css_parsing_utils.h` 中定义的工具函数。

总之，`css_parsing_utils_test.cc` 是 Blink 引擎中一个非常重要的测试文件，它确保了 CSS 解析工具函数的正确性，这直接关系到网页样式的正确渲染。通过阅读和理解这个文件，可以深入了解 Blink 引擎是如何处理各种 CSS 语法的。

### 提示词
```
这是目录为blink/renderer/core/css/properties/css_parsing_utils_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/properties/css_parsing_utils.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token_stream.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {
namespace {

using css_parsing_utils::AtDelimiter;
using css_parsing_utils::AtIdent;
using css_parsing_utils::ConsumeAngle;
using css_parsing_utils::ConsumeIfDelimiter;
using css_parsing_utils::ConsumeIfIdent;

CSSParserContext* MakeContext(CSSParserMode mode = kHTMLStandardMode) {
  return MakeGarbageCollected<CSSParserContext>(
      mode, SecureContextMode::kInsecureContext);
}

TEST(CSSParsingUtilsTest, BasicShapeUseCount) {
  test::TaskEnvironment task_environment;
  auto dummy_page_holder =
      std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
  Page::InsertOrdinaryPageForTesting(&dummy_page_holder->GetPage());
  Document& document = dummy_page_holder->GetDocument();
  WebFeature feature = WebFeature::kCSSBasicShape;
  EXPECT_FALSE(document.IsUseCounted(feature));
  document.documentElement()->setInnerHTML(
      "<style>span { shape-outside: circle(); }</style>");
  EXPECT_TRUE(document.IsUseCounted(feature));
}

TEST(CSSParsingUtilsTest, Revert) {
  EXPECT_TRUE(css_parsing_utils::IsCSSWideKeyword(CSSValueID::kRevert));
  EXPECT_TRUE(css_parsing_utils::IsCSSWideKeyword("revert"));
}

double ConsumeAngleValue(String target) {
  CSSParserTokenStream stream(target);
  return ConsumeAngle(stream, *MakeContext(), std::nullopt)->ComputeDegrees();
}

double ConsumeAngleValue(String target, double min, double max) {
  CSSParserTokenStream stream(target);
  return ConsumeAngle(stream, *MakeContext(), std::nullopt, min, max)
      ->ComputeDegrees();
}

TEST(CSSParsingUtilsTest, ConsumeAngles) {
  const double kMaxDegreeValue = 2867080569122160;

  EXPECT_EQ(10.0, ConsumeAngleValue("10deg"));
  EXPECT_EQ(-kMaxDegreeValue, ConsumeAngleValue("-3.40282e+38deg"));
  EXPECT_EQ(kMaxDegreeValue, ConsumeAngleValue("3.40282e+38deg"));

  EXPECT_EQ(kMaxDegreeValue, ConsumeAngleValue("calc(infinity * 1deg)"));
  EXPECT_EQ(-kMaxDegreeValue, ConsumeAngleValue("calc(-infinity * 1deg)"));
  EXPECT_EQ(kMaxDegreeValue, ConsumeAngleValue("calc(NaN * 1deg)"));

  // Math function with min and max ranges

  EXPECT_EQ(-100, ConsumeAngleValue("calc(-3.40282e+38deg)", -100, 100));
  EXPECT_EQ(100, ConsumeAngleValue("calc(3.40282e+38deg)", -100, 100));
}

TEST(CSSParsingUtilsTest, AtIdent) {
  String text = "foo,bar,10px";
  CSSParserTokenStream stream(text);
  EXPECT_FALSE(AtIdent(stream.Peek(), "bar"));  // foo
  stream.Consume();
  EXPECT_FALSE(AtIdent(stream.Peek(), "bar"));  // ,
  stream.Consume();
  EXPECT_TRUE(AtIdent(stream.Peek(), "bar"));  // bar
  stream.Consume();
  EXPECT_FALSE(AtIdent(stream.Peek(), "bar"));  // ,
  stream.Consume();
  EXPECT_FALSE(AtIdent(stream.Peek(), "bar"));  // 10px
  stream.Consume();
  EXPECT_FALSE(AtIdent(stream.Peek(), "bar"));  // EOF
  stream.Consume();
}

TEST(CSSParsingUtilsTest, ConsumeIfIdent) {
  String text = "foo,bar,10px";
  CSSParserTokenStream stream(text);
  EXPECT_TRUE(AtIdent(stream.Peek(), "foo"));
  EXPECT_FALSE(ConsumeIfIdent(stream, "bar"));
  EXPECT_TRUE(AtIdent(stream.Peek(), "foo"));
  EXPECT_TRUE(ConsumeIfIdent(stream, "foo"));
  EXPECT_EQ(kCommaToken, stream.Peek().GetType());
}

TEST(CSSParsingUtilsTest, AtDelimiter) {
  String text = "foo,<,10px";
  CSSParserTokenStream stream(text);
  EXPECT_FALSE(AtDelimiter(stream.Peek(), '<'));  // foo
  stream.Consume();
  EXPECT_FALSE(AtDelimiter(stream.Peek(), '<'));  // ,
  stream.Consume();
  EXPECT_TRUE(AtDelimiter(stream.Peek(), '<'));  // <
  stream.Consume();
  EXPECT_FALSE(AtDelimiter(stream.Peek(), '<'));  // ,
  stream.Consume();
  EXPECT_FALSE(AtDelimiter(stream.Peek(), '<'));  // 10px
  stream.Consume();
  EXPECT_FALSE(AtDelimiter(stream.Peek(), '<'));  // EOF
  stream.Consume();
}

TEST(CSSParsingUtilsTest, ConsumeIfDelimiter) {
  String text = "<,=,10px";
  CSSParserTokenStream stream(text);
  EXPECT_TRUE(AtDelimiter(stream.Peek(), '<'));
  EXPECT_FALSE(ConsumeIfDelimiter(stream, '='));
  EXPECT_TRUE(AtDelimiter(stream.Peek(), '<'));
  EXPECT_TRUE(ConsumeIfDelimiter(stream, '<'));
  EXPECT_EQ(kCommaToken, stream.Peek().GetType());
}

TEST(CSSParsingUtilsTest, ConsumeAnyValue_Stream) {
  struct {
    // The input string to parse as <any-value>.
    const char* input;
    // The serialization of the tokens remaining in the stream.
    const char* remainder;
  } tests[] = {
      {"1", ""},
      {"1px", ""},
      {"1px ", ""},
      {"ident", ""},
      {"(([ident]))", ""},
      {" ( ( 1 ) ) ", ""},
      {"rgb(1, 2, 3)", ""},
      {"rgb(1, 2, 3", ""},
      {"!!!;;;", ""},
      {"asdf)", ")"},
      {")asdf", ")asdf"},
      {"(ab)cd) e", ") e"},
      {"(as]df) e", "(as]df) e"},
      {"(a b [ c { d ) e } f ] g h) i", "(a b [ c { d ) e } f ] g h) i"},
      {"a url(() b", "url(() b"},
  };

  for (const auto& test : tests) {
    String input(test.input);
    SCOPED_TRACE(input);
    CSSParserTokenStream stream(input);
    css_parsing_utils::ConsumeAnyValue(stream);
    EXPECT_EQ(String(test.remainder), stream.RemainingText().ToString());
  }
}

TEST(CSSParsingUtilsTest, DashedIdent) {
  struct Expectations {
    String css_text;
    bool is_dashed_indent;
  } expectations[] = {
      {"--grogu", true}, {"--1234", true}, {"--\U0001F37A", true},
      {"--", true},      {"-", false},     {"blue", false},
      {"body", false},   {"0", false},     {"#FFAA00", false},
  };
  for (auto& expectation : expectations) {
    CSSParserTokenStream stream(expectation.css_text);
    EXPECT_EQ(css_parsing_utils::IsDashedIdent(stream.Peek()),
              expectation.is_dashed_indent);
  }
}

TEST(CSSParsingUtilsTest, ConsumeAbsoluteColor) {
  auto ConsumeColorForTest = [](String css_text, auto func) {
    CSSParserTokenStream stream(css_text);
    CSSParserContext* context = MakeContext();
    return func(stream, *context);
  };

  struct {
    STACK_ALLOCATED();

   public:
    String css_text;
    CSSIdentifierValue* consume_color_expectation;
    CSSIdentifierValue* consume_absolute_color_expectation;
  } expectations[]{
      {"Canvas", CSSIdentifierValue::Create(CSSValueID::kCanvas), nullptr},
      {"HighlightText", CSSIdentifierValue::Create(CSSValueID::kHighlighttext),
       nullptr},
      {"GrayText", CSSIdentifierValue::Create(CSSValueID::kGraytext), nullptr},
      {"blue", CSSIdentifierValue::Create(CSSValueID::kBlue),
       CSSIdentifierValue::Create(CSSValueID::kBlue)},
      // Deprecated system colors are not allowed either.
      {"ActiveBorder", CSSIdentifierValue::Create(CSSValueID::kActiveborder),
       nullptr},
      {"WindowText", CSSIdentifierValue::Create(CSSValueID::kWindowtext),
       nullptr},
      {"currentcolor", CSSIdentifierValue::Create(CSSValueID::kCurrentcolor),
       nullptr},
  };
  for (auto& expectation : expectations) {
    EXPECT_EQ(ConsumeColorForTest(expectation.css_text,
                                  css_parsing_utils::ConsumeColor),
              expectation.consume_color_expectation);
    EXPECT_EQ(ConsumeColorForTest(expectation.css_text,
                                  css_parsing_utils::ConsumeAbsoluteColor),
              expectation.consume_absolute_color_expectation);
  }
}

TEST(CSSParsingUtilsTest, InternalColorsOnlyAllowedInUaMode) {
  auto ConsumeColorForTest = [](String css_text, CSSParserMode mode) {
    CSSParserTokenStream stream(css_text);
    return css_parsing_utils::ConsumeColor(stream, *MakeContext(mode));
  };

  struct {
    STACK_ALLOCATED();

   public:
    String css_text;
    CSSIdentifierValue* ua_expectation;
    CSSIdentifierValue* other_expectation;
  } expectations[]{
      {"blue", CSSIdentifierValue::Create(CSSValueID::kBlue),
       CSSIdentifierValue::Create(CSSValueID::kBlue)},
      {"-internal-spelling-error-color",
       CSSIdentifierValue::Create(CSSValueID::kInternalSpellingErrorColor),
       nullptr},
      {"-internal-grammar-error-color",
       CSSIdentifierValue::Create(CSSValueID::kInternalGrammarErrorColor),
       nullptr},
      {"-internal-search-color",
       CSSIdentifierValue::Create(CSSValueID::kInternalSearchColor), nullptr},
      {"-internal-search-text-color",
       CSSIdentifierValue::Create(CSSValueID::kInternalSearchTextColor),
       nullptr},
      {"-internal-current-search-color",
       CSSIdentifierValue::Create(CSSValueID::kInternalCurrentSearchColor),
       nullptr},
      {"-internal-current-search-text-color",
       CSSIdentifierValue::Create(CSSValueID::kInternalCurrentSearchTextColor),
       nullptr},
  };
  for (auto& expectation : expectations) {
    EXPECT_EQ(ConsumeColorForTest(expectation.css_text, kHTMLStandardMode),
              expectation.other_expectation);
    EXPECT_EQ(ConsumeColorForTest(expectation.css_text, kHTMLQuirksMode),
              expectation.other_expectation);
    EXPECT_EQ(ConsumeColorForTest(expectation.css_text, kUASheetMode),
              expectation.ua_expectation);
  }
}

// Verify that the state of CSSParserTokenStream is preserved
// for failing <color> values.
TEST(CSSParsingUtilsTest, ConsumeColorRangePreservation) {
  const char* tests[] = {
      "color-mix(42deg)",
      "color-contrast(42deg)",
  };
  for (const char*& test : tests) {
    String input(test);
    SCOPED_TRACE(input);
    CSSParserTokenStream stream(input);
    EXPECT_EQ(nullptr, css_parsing_utils::ConsumeColor(stream, *MakeContext()));
    EXPECT_EQ(test, stream.RemainingText());
  }
}

TEST(CSSParsingUtilsTest, InternalPositionTryFallbacksInUAMode) {
  auto ConsumePositionTryFallbackForTest = [](String css_text,
                                              CSSParserMode mode) {
    CSSParserTokenStream stream(css_text);
    return css_parsing_utils::ConsumeSinglePositionTryFallback(
        stream, *MakeContext(mode));
  };

  struct {
    STACK_ALLOCATED();

   public:
    String css_text;
    bool allow_ua;
    bool allow_other;
  } expectations[]{
      {.css_text = "--foo", .allow_ua = true, .allow_other = true},
      {.css_text = "-foo", .allow_ua = false, .allow_other = false},
      {.css_text = "-internal-foo", .allow_ua = true, .allow_other = false},
  };
  for (auto& expectation : expectations) {
    EXPECT_EQ(ConsumePositionTryFallbackForTest(expectation.css_text,
                                                kHTMLStandardMode) != nullptr,
              expectation.allow_other);
    EXPECT_EQ(ConsumePositionTryFallbackForTest(expectation.css_text,
                                                kHTMLQuirksMode) != nullptr,
              expectation.allow_other);
    EXPECT_EQ(ConsumePositionTryFallbackForTest(expectation.css_text,
                                                kUASheetMode) != nullptr,
              expectation.allow_ua);
  }
}

// crbug.com/364340016
TEST(CSSParsingUtilsTest, ConsumePositionTryFallbacksInUAMode) {
  String css_text = "block-start span-inline-end";
  CSSParserTokenStream stream(css_text);
  CSSValue* value = css_parsing_utils::ConsumePositionTryFallbacks(
      stream, *MakeContext(kUASheetMode));
  ASSERT_TRUE(value);
  EXPECT_EQ("block-start span-inline-end", value->CssText());
}

}  // namespace
}  // namespace blink
```