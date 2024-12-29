Response:
Let's break down the thought process for analyzing the `css_supports_parser_test.cc` file.

1. **Understanding the Goal:** The primary goal is to analyze the provided C++ test file and explain its purpose, its relationship to web technologies, provide examples, and discuss debugging.

2. **Initial Scan and Keyword Recognition:**  I first scanned the file for recognizable keywords and patterns. Things that immediately stood out:
    * `#include`: This signifies C++ and dependency management. The included headers (`gtest/gtest.h`, various `blink` headers) are crucial.
    * `namespace blink`:  Confirms this is part of the Blink rendering engine.
    * `CSSSupportsParser`, `ConsumeSupportsCondition`, `ConsumeSupportsInParens`, etc.: These names strongly suggest the file is related to the CSS `@supports` rule.
    * `TEST_F`: This is the GTest framework for writing unit tests.
    * `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`: These are GTest assertion macros, indicating the file contains tests that verify expected behavior.
    * `Result::kSupported`, `Result::kUnsupported`, `Result::kParseFailure`:  These enums likely represent the outcome of parsing the `@supports` condition.

3. **Inferring Functionality from Names and Includes:**  Based on the keywords, I could infer:
    * This file tests the `CSSSupportsParser` class.
    * The `CSSSupportsParser` is responsible for parsing the conditions within the CSS `@supports` rule.
    * The included headers suggest it interacts with other CSS parsing components like `CSSTokenizer`, `CSSParserImpl`, and `CSSParserTokenStream`.

4. **Analyzing the Test Structure:** The `CSSSupportsParserTest` class sets up a testing fixture. The helper methods within this class (like `MakeContext`, `Tokenize`, `StaticConsumeSupportsCondition`, etc.) are designed to facilitate testing different parsing scenarios. They abstract away some of the lower-level setup needed for the parser.

5. **Connecting to Web Technologies:** The presence of "CSS" in the class and method names immediately connects this to the CSS language. The `@supports` rule is a specific CSS feature. I recalled that `@supports` allows developers to conditionally apply CSS styles based on browser support for certain CSS features. This naturally leads to the connection with HTML (as CSS styles HTML elements) and JavaScript (which can manipulate styles and potentially interact with the results of `@supports` checks).

6. **Providing Examples (Crucial for Understanding):**  To illustrate the functionality, I started mapping the test cases to real-world CSS `@supports` syntax:
    * `ConsumeSupportsCondition("not (asdf:red)")`:  Maps to `not (property: value)`.
    * `ConsumeSupportsCondition("(color:red) and (color:green)")`: Maps to `(property: value) and (property: value)`.
    * `ConsumeSupportsSelectorFn("selector(div)")`: Maps to `selector(selector)`.
    * `ConsumeSupportsDecl("(color:red)")`: Maps to `(property: value)`.

7. **Explaining the Logic (Assumptions and Outputs):** The test cases inherently demonstrate the logic. Each `EXPECT_EQ`/`EXPECT_TRUE`/`EXPECT_FALSE` represents an assumption about the parser's output for a given input. For instance:
    * **Assumption:**  The parser should recognize "color: red" as a supported declaration.
    * **Input:** `ConsumeSupportsDecl("(color:red)")`
    * **Expected Output:** `true` (using `EXPECT_TRUE`).

8. **Considering User/Programming Errors:**  I thought about common mistakes when using the `@supports` rule:
    * **Incorrect Syntax:**  Missing parentheses, incorrect keywords, invalid property/value combinations.
    * **Logical Errors:**  Misunderstanding the `and`/`or`/`not` operators.
    * **Browser Compatibility Issues:**  Assuming a feature is supported when it's not.

9. **Tracing User Operations (Debugging Context):**  I considered how a user might end up encountering this code during debugging:
    * **Reporting a Bug:** A web developer notices that `@supports` isn't working as expected in Chrome. They might file a bug report, potentially leading a Chromium developer to investigate this test file.
    * **Developing a New Feature:**  A Chromium developer working on a new CSS feature might need to modify the `@supports` parsing logic and would use these tests to ensure their changes don't break existing functionality.
    * **Investigating a Crash:**  A crash related to CSS parsing could lead a developer to examine the `@supports` parser.

10. **Refining and Organizing:** Finally, I organized the information into clear sections with headings and bullet points for readability. I made sure to explain the relationships between the test file, the `CSSSupportsParser` class, and the broader web technologies. I aimed for a comprehensive yet understandable explanation.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the C++ specifics. I realized the importance of connecting it back to the user-facing web technologies (HTML, CSS, JavaScript).
* I made sure to include concrete examples of CSS syntax that correspond to the test cases, as this makes the explanation much clearer.
* I initially might have just listed the functions without clearly explaining their purpose. I refined this to explain *what* each function does in the context of parsing `@supports` conditions.
* I ensured the "User Operations" section provided a plausible debugging scenario, rather than just stating the file exists.

By following this systematic approach, analyzing the code, connecting it to relevant concepts, providing examples, and considering practical usage, I was able to generate a comprehensive and informative explanation of the `css_supports_parser_test.cc` file.
这个文件 `blink/renderer/core/css/parser/css_supports_parser_test.cc` 是 Chromium Blink 引擎中的一个 **单元测试文件**。它的主要功能是 **测试 `CSSSupportsParser` 类的各种方法，以确保 `@supports` CSS 规则的解析器能够正确地解析和判断各种条件表达式的真假。**

更具体地说，它测试了以下方面的功能：

1. **`CSSSupportsParser::ConsumeSupportsCondition()`:**  测试解析 `@supports` 规则中完整条件表达式的能力，包括 `not`、`and`、`or` 运算符以及嵌套的括号。
2. **`CSSSupportsParser::ConsumeSupportsInParens()`:** 测试解析括号内的条件表达式，这通常是构成更复杂条件的基础。
3. **`CSSSupportsParser::ConsumeSupportsFeature()`:** 测试解析简单的特性查询，例如 `(color: red)`。
4. **`CSSSupportsParser::ConsumeSupportsSelectorFn()`:** 测试解析 `selector()` 函数，用于检查浏览器是否支持特定的 CSS 选择器。
5. **`CSSSupportsParser::ConsumeSupportsDecl()`:** 测试解析声明支持，即检查浏览器是否支持特定的 CSS 属性及其值，例如 `(color: red)`.
6. **`CSSSupportsParser::ConsumeGeneralEnclosed()`:** 测试解析一般封闭的内容，这在 `@supports` 规则中可能出现。

**它与 javascript, html, css 的功能有关系，并举例说明：**

这个测试文件直接关系到 **CSS** 的功能，特别是 **`@supports` 规则**。`@supports` 规则允许开发者编写根据浏览器对特定 CSS 特性的支持情况而应用的 CSS 声明。

* **CSS:**  该测试文件验证了 Blink 引擎是否能正确解析和理解 CSS 的 `@supports` 规则。 例如，测试用例 `EXPECT_EQ(Result::kSupported, ConsumeSupportsCondition("(color:red)"));` 就直接关联到 CSS 属性 `color` 和值 `red` 的支持情况。

* **HTML:**  `@supports` 规则最终会影响 HTML 页面的渲染。根据 `@supports` 的判断结果，某些 CSS 样式可能会被应用到 HTML 元素上。例如，如果在 CSS 中有 `@supports (display: grid) { ... }`，那么只有当浏览器支持 CSS Grid 布局时，花括号内的样式才会应用于 HTML 元素。虽然这个测试文件不直接操作 HTML，但它确保了 `@supports` 规则的正确性，从而间接地影响 HTML 的呈现。

* **JavaScript:** JavaScript 可以通过 `CSS.supports()` API 来查询浏览器对特定 CSS 属性或选择器的支持情况，其底层的解析逻辑与 `CSSSupportsParser` 类似。  这个测试文件验证了 Blink 引擎的解析器，其结果会影响到 `CSS.supports()` API 的返回值。 例如，JavaScript 代码 `CSS.supports('display', 'grid')` 的结果，会受到 `CSSSupportsParser` 中关于 `display: grid` 解析的正确性的影响。

**逻辑推理，给出假设输入与输出:**

以下是一些从测试用例中提取的逻辑推理示例：

**假设输入 1:**  `ConsumeSupportsCondition("not (color:red)")`

* **逻辑推理:** 如果浏览器 *不支持* `color: red` 这个特性，那么 `(color:red)` 的结果是 `kUnsupported`。 `not` 运算符会将其取反，因此整个表达式的结果应该是 `kSupported`。
* **预期输出:** `Result::kSupported`

**假设输入 2:** `ConsumeSupportsCondition("(color:red) and (display:grid)")`

* **逻辑推理:** 只有当浏览器 *同时支持* `color: red` 和 `display: grid` 这两个特性时，整个表达式的结果才是 `kSupported`。如果其中任何一个不支持，结果就是 `kUnsupported`。
* **预期输出 (取决于浏览器支持情况):** 如果浏览器同时支持 `color: red` 和 `display: grid`，则输出 `Result::kSupported`。 否则，输出 `Result::kUnsupported`。 在测试中，会模拟不同的支持情况进行验证。

**假设输入 3:** `ConsumeSupportsSelectorFn("selector(div.cls)")`

* **逻辑推理:**  这个测试检查解析器是否能正确识别 `selector()` 函数，并判断提供的 CSS 选择器 `div.cls` (选择 class 为 `cls` 的 `div` 元素) 是否是有效的语法。
* **预期输出:** `true` (因为 `div.cls` 是一个有效的 CSS 选择器)

**涉及用户或者编程常见的使用错误，并举例说明:**

这个测试文件可以帮助发现和防止用户或开发者在使用 `@supports` 规则时可能出现的错误，以及 Blink 引擎在解析这些错误时的行为。

* **语法错误:** 例如，用户可能会忘记闭合括号：`@supports (color:red`。 测试用例如 `EXPECT_EQ(Result::kParseFailure, ConsumeSupportsInParens("(color]asdf)"));` 就覆盖了类似的语法错误，确保解析器能正确识别并返回 `kParseFailure`。

* **逻辑错误:** 用户可能会错误地使用 `and` 和 `or` 运算符，导致 `@supports` 规则的行为不符合预期。 例如，`@supports (color: red) and (display: block)`  只有在同时支持 `color: red` 和 `display: block` 时才生效。如果用户错误地以为只要支持其中一个就生效，那就是逻辑错误。 测试用例通过各种 `and` 和 `or` 的组合来验证解析器的逻辑正确性，间接地帮助用户理解这些运算符的行为。

* **不支持的特性:** 用户可能会尝试使用一些浏览器不支持的 CSS 特性放在 `@supports` 规则中。 测试用例通过模拟不支持的特性 (例如 `asdf:red`) 来验证解析器在这种情况下返回 `kUnsupported`。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

作为一个开发者，当遇到与 `@supports` 规则相关的 bug 时，可能会逐步深入到这个测试文件进行调试：

1. **用户报告问题:** 用户可能发现某个使用了 `@supports` 规则的网页在 Chrome 浏览器中的样式显示不正确。
2. **前端开发调试:** 前端开发人员会检查 CSS 代码，确认 `@supports` 规则的语法没有错误，并且浏览器理应支持声明的特性。他们可能会使用浏览器的开发者工具查看样式是否被应用，以及 `CSS.supports()` 的返回值。
3. **Blink 引擎开发者介入:** 如果问题看起来是浏览器解析 `@supports` 规则的方式有问题，那么负责 Blink 渲染引擎的开发者可能会介入。
4. **定位相关代码:** 开发者可能会搜索 Blink 源代码中与 `@supports` 相关的代码，找到 `CSSSupportsParser` 类及其相关的测试文件 `css_supports_parser_test.cc`。
5. **分析测试用例:** 开发者会分析这个测试文件中的各种测试用例，看看是否有现有的测试覆盖了用户报告的问题场景。
6. **添加或修改测试用例:** 如果没有相关的测试用例，开发者会添加一个新的测试用例来重现用户报告的问题。如果现有的测试用例失败了，那么就说明了 `@supports` 解析器存在 bug。
7. **调试 `CSSSupportsParser` 代码:** 开发者会使用调试器 (例如 gdb) 来单步执行 `CSSSupportsParser` 类的代码，分析在解析用户提供的 CSS 代码时，解析器的状态和行为，找出导致解析错误的原因。
8. **修复 Bug:**  找到 bug 后，开发者会修改 `CSSSupportsParser` 的代码来修复这个问题。
9. **运行测试:** 修复代码后，开发者会重新运行所有的测试用例，包括 `css_supports_parser_test.cc` 中的测试，确保修复没有引入新的问题。

总而言之，`css_supports_parser_test.cc` 文件是 Blink 引擎中至关重要的一个测试文件，它确保了 CSS `@supports` 规则的解析器能够正确地工作，从而保证了网页在不同浏览器中样式的一致性和可靠性。 开发者通过编写和维护这些测试用例，可以有效地预防和修复与 `@supports` 规则相关的 bug。

Prompt: 
```
这是目录为blink/renderer/core/css/parser/css_supports_parser_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/parser/css_supports_parser.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_impl.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token_stream.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"

namespace blink {

using Result = CSSSupportsParser::Result;

class CSSSupportsParserTest : public testing::Test {
 public:
  CSSParserContext* MakeContext() {
    return MakeGarbageCollected<CSSParserContext>(
        kHTMLStandardMode, SecureContextMode::kInsecureContext);
  }

  Vector<CSSParserToken, 32> Tokenize(const String& string) {
    CSSTokenizer tokenizer(string);
    Vector<CSSParserToken, 32> tokens;
    while (true) {
      const CSSParserToken token = tokenizer.TokenizeSingle();
      if (token.GetType() == kEOFToken) {
        return tokens;
      } else {
        tokens.push_back(token);
      }
    }
  }

  Result StaticConsumeSupportsCondition(String string) {
    CSSParserImpl impl(MakeContext());
    CSSParserTokenStream stream(string);
    Result result = CSSSupportsParser::ConsumeSupportsCondition(stream, impl);
    return stream.AtEnd() ? result : Result::kParseFailure;
  }

  Result AtSupports(String string) {
    return StaticConsumeSupportsCondition(string);
  }

  Result WindowCSSSupports(String string) {
    String wrapped_condition = "(" + string + ")";
    return StaticConsumeSupportsCondition(wrapped_condition);
  }

  Result ConsumeSupportsCondition(String string) {
    CSSParserImpl impl(MakeContext());
    CSSSupportsParser parser(impl);
    CSSParserTokenStream stream(string);
    return parser.ConsumeSupportsCondition(stream);
  }

  Result ConsumeSupportsInParens(String string) {
    CSSParserImpl impl(MakeContext());
    CSSSupportsParser parser(impl);
    CSSParserTokenStream stream(string);
    return parser.ConsumeSupportsInParens(stream);
  }

  bool ConsumeSupportsFeature(String string) {
    CSSParserImpl impl(MakeContext());
    CSSSupportsParser parser(impl);
    CSSParserTokenStream stream(string);
    return parser.ConsumeSupportsFeature(stream);
  }

  bool ConsumeSupportsSelectorFn(String string) {
    CSSParserImpl impl(MakeContext());
    CSSSupportsParser parser(impl);
    CSSParserTokenStream stream(string);
    return parser.ConsumeSupportsSelectorFn(stream);
  }

  bool ConsumeSupportsDecl(String string) {
    CSSParserImpl impl(MakeContext());
    CSSSupportsParser parser(impl);
    CSSParserTokenStream stream(string);
    return parser.ConsumeSupportsDecl(stream);
  }

  bool ConsumeGeneralEnclosed(String string) {
    CSSParserImpl impl(MakeContext());
    CSSSupportsParser parser(impl);
    CSSParserTokenStream stream(string);
    return parser.ConsumeGeneralEnclosed(stream);
  }
};

TEST_F(CSSSupportsParserTest, ResultNot) {
  EXPECT_EQ(Result::kSupported, !Result::kUnsupported);
  EXPECT_EQ(Result::kUnsupported, !Result::kSupported);
  EXPECT_EQ(Result::kParseFailure, !Result::kParseFailure);
}

TEST_F(CSSSupportsParserTest, ResultAnd) {
  EXPECT_EQ(Result::kSupported, Result::kSupported & Result::kSupported);
  EXPECT_EQ(Result::kUnsupported, Result::kUnsupported & Result::kSupported);
  EXPECT_EQ(Result::kUnsupported, Result::kSupported & Result::kUnsupported);
  EXPECT_EQ(Result::kUnsupported, Result::kUnsupported & Result::kUnsupported);

  EXPECT_EQ(Result::kParseFailure, Result::kSupported & Result::kParseFailure);
  EXPECT_EQ(Result::kParseFailure, Result::kParseFailure & Result::kSupported);
}

TEST_F(CSSSupportsParserTest, ResultOr) {
  EXPECT_EQ(Result::kSupported, Result::kSupported | Result::kSupported);
  EXPECT_EQ(Result::kSupported, Result::kUnsupported | Result::kSupported);
  EXPECT_EQ(Result::kSupported, Result::kSupported | Result::kUnsupported);
  EXPECT_EQ(Result::kUnsupported, Result::kUnsupported | Result::kUnsupported);

  EXPECT_EQ(Result::kParseFailure, Result::kSupported | Result::kParseFailure);
  EXPECT_EQ(Result::kParseFailure, Result::kParseFailure | Result::kSupported);
}

TEST_F(CSSSupportsParserTest, ConsumeSupportsCondition) {
  // not <supports-in-parens>
  EXPECT_EQ(Result::kSupported, ConsumeSupportsCondition("not (asdf:red)"));
  EXPECT_EQ(Result::kUnsupported,
            ConsumeSupportsCondition("(not (color:red))"));
  EXPECT_EQ(Result::kParseFailure, ConsumeSupportsCondition("nay (color:red)"));

  // <supports-in-parens> [ and <supports-in-parens> ]*
  EXPECT_EQ(Result::kSupported,
            ConsumeSupportsCondition("(color:red) and (color:green)"));
  EXPECT_EQ(Result::kUnsupported,
            ConsumeSupportsCondition("(color:red) and (asdf:green)"));
  EXPECT_EQ(Result::kUnsupported,
            ConsumeSupportsCondition("(asdf:red) and (asdf:green)"));
  EXPECT_EQ(Result::kUnsupported,
            ConsumeSupportsCondition(
                "(color:red) and (color:green) and (asdf:color)"));
  EXPECT_EQ(Result::kSupported,
            ConsumeSupportsCondition(
                "(color:red) and (color:green) and (not (asdf:color))"));

  // <supports-in-parens> [ or <supports-in-parens> ]*
  EXPECT_EQ(Result::kSupported,
            ConsumeSupportsCondition("(color:red) or (color:asdf)"));
  EXPECT_EQ(Result::kSupported,
            ConsumeSupportsCondition("(color:asdf) or (color:green)"));
  EXPECT_EQ(Result::kUnsupported,
            ConsumeSupportsCondition("(asdf:red) or (asdf:green)"));
  EXPECT_EQ(
      Result::kSupported,
      ConsumeSupportsCondition("(color:red) or (color:green) or (asdf:color)"));
  EXPECT_EQ(Result::kUnsupported,
            ConsumeSupportsCondition(
                "(color:asdf1) or (color:asdf2) or (asdf:asdf2)"));
  EXPECT_EQ(Result::kSupported,
            ConsumeSupportsCondition(
                "(color:asdf) or (color:ghjk) or (not (asdf:color))"));

  // <supports-feature>
  EXPECT_EQ(Result::kSupported, ConsumeSupportsCondition("(color:red)"));
  EXPECT_EQ(Result::kUnsupported, ConsumeSupportsCondition("(color:asdf)"));

  // <general-enclosed>
  EXPECT_EQ(Result::kUnsupported, ConsumeSupportsCondition("asdf(1)"));
  EXPECT_EQ(Result::kUnsupported, ConsumeSupportsCondition("asdf()"));
}

TEST_F(CSSSupportsParserTest, ConsumeSupportsInParens) {
  // ( <supports-condition> )
  EXPECT_EQ(Result::kSupported, ConsumeSupportsInParens("(not (asdf:red))"));
  EXPECT_EQ(Result::kUnsupported, ConsumeSupportsInParens("(not (color:red))"));
  EXPECT_EQ(Result::kParseFailure,
            ConsumeSupportsInParens("(not (color:red)])"));

  EXPECT_EQ(Result::kUnsupported,
            ConsumeSupportsInParens("(not ( (color:gjhk) or (color:red) ))"));
  EXPECT_EQ(
      Result::kUnsupported,
      ConsumeSupportsInParens("(not ( ((color:gjhk)) or (color:blue) ))"));
  EXPECT_EQ(Result::kSupported,
            ConsumeSupportsInParens("(( (color:gjhk) or (color:red) ))"));
  EXPECT_EQ(Result::kSupported,
            ConsumeSupportsInParens("(( ((color:gjhk)) or (color:blue) ))"));

  // <supports-feature>
  EXPECT_EQ(Result::kSupported, ConsumeSupportsInParens("(color:red)"));
  EXPECT_EQ(Result::kUnsupported, ConsumeSupportsInParens("(color:asdf)"));
  EXPECT_EQ(Result::kParseFailure, ConsumeSupportsInParens("(color]asdf)"));

  // <general-enclosed>
  EXPECT_EQ(Result::kUnsupported, ConsumeSupportsInParens("asdf(1)"));
  EXPECT_EQ(Result::kUnsupported, ConsumeSupportsInParens("asdf()"));

  EXPECT_EQ(Result::kSupported,
            ConsumeSupportsInParens("(color:red)and (color:green)"));
  EXPECT_EQ(Result::kSupported,
            ConsumeSupportsInParens("(color:red)or (color:green)"));
  EXPECT_EQ(Result::kSupported,
            ConsumeSupportsInParens("selector(div)or (color:green)"));
  EXPECT_EQ(Result::kSupported,
            ConsumeSupportsInParens("selector(div)and (color:green)"));

  // Invalid <supports-selector-fn> formerly handled by
  // ConsumeSupportsSelectorFn()
  EXPECT_EQ(Result::kParseFailure, ConsumeSupportsInParens("#test"));
  EXPECT_EQ(Result::kParseFailure, ConsumeSupportsInParens("test"));

  // Invalid <supports-selector-fn> but valid <general-enclosed>
  EXPECT_EQ(Result::kUnsupported, ConsumeSupportsInParens("test(1)"));

  // Invalid <supports-decl> formerly handled by ConsumeSupportsDecl()
  EXPECT_EQ(Result::kParseFailure, ConsumeSupportsInParens(""));
  EXPECT_EQ(Result::kParseFailure, ConsumeSupportsInParens(")"));
  EXPECT_EQ(Result::kParseFailure, ConsumeSupportsInParens("color:red)"));
  EXPECT_EQ(Result::kParseFailure, ConsumeSupportsInParens("color:red"));

  // Invalid <general-enclosed> formerly handled by ConsumeGeneralEnclosed()
  EXPECT_EQ(Result::kParseFailure, ConsumeSupportsInParens(""));
  EXPECT_EQ(Result::kParseFailure, ConsumeSupportsInParens(")"));
  EXPECT_EQ(Result::kParseFailure, ConsumeSupportsInParens("color:red"));
  EXPECT_EQ(Result::kParseFailure, ConsumeSupportsInParens("asdf"));
}

TEST_F(CSSSupportsParserTest, ConsumeSupportsSelectorFn) {
  EXPECT_TRUE(ConsumeSupportsSelectorFn("selector(*)"));
  EXPECT_TRUE(ConsumeSupportsSelectorFn("selector(*:hover)"));
  EXPECT_TRUE(ConsumeSupportsSelectorFn("selector(:hover)"));
  EXPECT_TRUE(ConsumeSupportsSelectorFn("selector(::before)"));
  EXPECT_TRUE(ConsumeSupportsSelectorFn("selector(div)"));
  EXPECT_TRUE(ConsumeSupportsSelectorFn("selector(div"));
  EXPECT_TRUE(ConsumeSupportsSelectorFn("selector(.a)"));
  EXPECT_TRUE(ConsumeSupportsSelectorFn("selector(#a)"));
  EXPECT_TRUE(ConsumeSupportsSelectorFn("selector(div.a)"));
  EXPECT_TRUE(ConsumeSupportsSelectorFn("selector(div a)"));
  EXPECT_TRUE(ConsumeSupportsSelectorFn("selector(a > div)"));
  EXPECT_TRUE(ConsumeSupportsSelectorFn("selector(a ~ div)"));
  EXPECT_TRUE(ConsumeSupportsSelectorFn("selector(a + div)"));
  EXPECT_TRUE(ConsumeSupportsSelectorFn("selector(*|a)"));
  EXPECT_TRUE(ConsumeSupportsSelectorFn("selector(a + div#test)"));
  EXPECT_TRUE(ConsumeSupportsSelectorFn("selector(a + div#test::before)"));
  EXPECT_TRUE(ConsumeSupportsSelectorFn("selector(a.cls:hover)"));
  EXPECT_TRUE(ConsumeSupportsSelectorFn("selector(a.cls::before)"));
  EXPECT_TRUE(ConsumeSupportsSelectorFn("selector(div::-webkit-clear-button)"));
  EXPECT_TRUE(ConsumeSupportsSelectorFn("selector(:is(.a))"));
  EXPECT_TRUE(ConsumeSupportsSelectorFn("selector(:where(.a))"));
  EXPECT_TRUE(ConsumeSupportsSelectorFn("selector(:has(.a))"));

  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(div::-webkit-asdf)"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(a + div::-webkit-asdf)"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(div.cls::-webkit-asdf)"));

  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(div.~cls)"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(div. ~cls)"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(div .~ cls)"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(div$ cls)"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(div $cls)"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(div $ cls)"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(unknown|a)"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(a::asdf)"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(a:asdf)"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(a, body)"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(*:asdf)"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(*::asdf)"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(:asdf)"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(::asdf)"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(:is())"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(:where())"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(:not())"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(:is(:foo))"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(:is(:has(:foo)))"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(:where(:foo))"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(:where(:has(:foo)))"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(:has(:foo))"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(:has(:is(:foo)))"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(:has(.a, :is(:foo)))"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(:has(.a, .b, :is(:foo)))"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(:is(.a, :foo))"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(:where(.a, :foo))"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(:has(.a, :foo))"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(:has(.a, .b, :foo))"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(:has(:has(.a)))"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(:has(:is(:has(.a))))"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(:has(:is(:has(.a), .b)))"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(:has(.a, :has(.b)))"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(:has(.a, .b, :has(.c)))"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(:host(:is(:foo)))"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(:host(:has(.a)))"));
  EXPECT_FALSE(ConsumeSupportsSelectorFn("selector(::part(foo):has(.a)))"));
}

TEST_F(CSSSupportsParserTest, ConsumeSupportsDecl) {
  EXPECT_TRUE(ConsumeSupportsDecl("(color:red)"));
  EXPECT_TRUE(ConsumeSupportsDecl("(color:    red)"));
  EXPECT_TRUE(ConsumeSupportsDecl("(color   : red)"));
  EXPECT_TRUE(ConsumeSupportsDecl("(color   :red)"));
  EXPECT_TRUE(ConsumeSupportsDecl("( color:red )"));
  EXPECT_TRUE(ConsumeSupportsDecl("(--x:red)"));
  EXPECT_TRUE(ConsumeSupportsDecl("(--x:\tred) "));
  EXPECT_TRUE(ConsumeSupportsDecl("(--x:\tred) \t "));
  EXPECT_TRUE(ConsumeSupportsDecl("(color:green !important)"));
  // For some reason EOF is allowed in place of ')' (everywhere in Blink).
  // Seems to be the case in Firefox too.
  EXPECT_TRUE(ConsumeSupportsDecl("(color:red"));

  EXPECT_FALSE(ConsumeSupportsDecl("(color:asdf)"));
  EXPECT_FALSE(ConsumeSupportsDecl("(asdf)"));
  EXPECT_FALSE(ConsumeSupportsDecl("(color)"));
  EXPECT_FALSE(ConsumeSupportsDecl("(color:)"));

  EXPECT_FALSE(ConsumeSupportsDecl("("));
  EXPECT_FALSE(ConsumeSupportsDecl("()"));
}

TEST_F(CSSSupportsParserTest, ConsumeSupportsFeature) {
  EXPECT_TRUE(ConsumeSupportsFeature("(color:red)"));
  EXPECT_FALSE(ConsumeSupportsFeature("asdf(1)"));
}

TEST_F(CSSSupportsParserTest, ConsumeGeneralEnclosed) {
  EXPECT_TRUE(ConsumeGeneralEnclosed("(asdf)"));
  EXPECT_TRUE(ConsumeGeneralEnclosed("( asdf )"));
  EXPECT_TRUE(ConsumeGeneralEnclosed("(3)"));
  EXPECT_TRUE(ConsumeGeneralEnclosed("max(1, 2)"));
  EXPECT_TRUE(ConsumeGeneralEnclosed("asdf(1, 2)"));
  EXPECT_TRUE(ConsumeGeneralEnclosed("asdf(1, 2)\t"));
  EXPECT_TRUE(ConsumeGeneralEnclosed("("));
  EXPECT_TRUE(ConsumeGeneralEnclosed("()"));
  EXPECT_TRUE(ConsumeGeneralEnclosed("( )"));

  // Invalid <any-value>:
  EXPECT_FALSE(ConsumeGeneralEnclosed("(asdf})"));
  EXPECT_FALSE(ConsumeGeneralEnclosed("(asd]f)"));
  EXPECT_FALSE(ConsumeGeneralEnclosed("(\"as\ndf\")"));
  EXPECT_FALSE(ConsumeGeneralEnclosed("(url(as'df))"));

  // Valid <any-value>
  EXPECT_TRUE(ConsumeGeneralEnclosed("(as;df)"));
  EXPECT_TRUE(ConsumeGeneralEnclosed("(as ! df)"));
}

TEST_F(CSSSupportsParserTest, AtSupportsCondition) {
  EXPECT_EQ(Result::kSupported, AtSupports("(--x:red)"));
  EXPECT_EQ(Result::kSupported, AtSupports("(--x:red) and (color:green)"));
  EXPECT_EQ(Result::kSupported, AtSupports("(--x:red) or (color:asdf)"));
  EXPECT_EQ(Result::kSupported,
            AtSupports("not ((color:gjhk) or (color:asdf))"));
  EXPECT_EQ(Result::kSupported,
            AtSupports("(display: none) and ( (display: none) )"));

  EXPECT_EQ(Result::kUnsupported, AtSupports("(color:ghjk) or (color:asdf)"));
  EXPECT_EQ(Result::kUnsupported, AtSupports("(color:ghjk) or asdf(1)"));
  EXPECT_EQ(Result::kParseFailure, AtSupports("color:red"));
  EXPECT_EQ(
      Result::kParseFailure,
      AtSupports("(display: none) and (display: block) or (display: inline)"));
  EXPECT_EQ(Result::kParseFailure,
            AtSupports("not (display: deadbeef) and (display: block)"));
  EXPECT_EQ(Result::kParseFailure,
            AtSupports("(margin: 0) and (display: inline) or (width:1em)"));

  // "and("/"or(" are function tokens, hence not allowed here.
  EXPECT_EQ(Result::kParseFailure, AtSupports("(left:0) and(top:0)"));
  EXPECT_EQ(Result::kParseFailure, AtSupports("(left:0) or(top:0)"));
}

TEST_F(CSSSupportsParserTest, WindowCSSSupportsCondition) {
  EXPECT_EQ(Result::kSupported, WindowCSSSupports("(--x:red)"));
  EXPECT_EQ(Result::kSupported, WindowCSSSupports("( --x:red )"));
  EXPECT_EQ(Result::kSupported,
            WindowCSSSupports("(--x:red) and (color:green)"));
  EXPECT_EQ(Result::kSupported, WindowCSSSupports("(--x:red) or (color:asdf)"));
  EXPECT_EQ(Result::kSupported,
            WindowCSSSupports("not ((color:gjhk) or (color:asdf))"));

  EXPECT_EQ(Result::kUnsupported,
            WindowCSSSupports("(color:ghjk) or (color:asdf)"));
  EXPECT_EQ(Result::kUnsupported, WindowCSSSupports("(color:ghjk) or asdf(1)"));
  EXPECT_EQ(Result::kSupported, WindowCSSSupports("color:red"));
}

}  // namespace blink

"""

```