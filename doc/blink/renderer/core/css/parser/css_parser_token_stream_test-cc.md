Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The primary goal is to understand the *purpose* of the file `css_parser_token_stream_test.cc`. This immediately signals that it's a unit test file. Therefore, the core function will be testing the behavior of the `CSSParserTokenStream` class.

2. **Identify the Target Class:** The `#include` directives are the first clue. `#include "third_party/blink/renderer/core/css/parser/css_parser_token_stream.h"` tells us the central class being tested is `CSSParserTokenStream`.

3. **High-Level Functionality of the Target Class:** Before diving into the tests, try to infer what `CSSParserTokenStream` likely does. Based on the name:
    * **CSS Parser:** It's involved in parsing CSS.
    * **Token Stream:**  It likely deals with a stream of tokens. This suggests it takes a raw CSS string and breaks it down into meaningful units (tokens).
    * **Stream:** Implies sequential access, potentially with the ability to peek ahead and consume.

4. **Examine the Test Structure:** The file uses the Google Test framework (`TEST(CSSParserTokenStreamTest, ...)`). This provides structure to the tests. Each `TEST` case focuses on a specific aspect of `CSSParserTokenStream`'s functionality.

5. **Analyze Individual Test Cases (Iterative Process):**  Go through each test case and try to understand what it's verifying. Focus on the key actions within each test:
    * **Instantiation:** How is `CSSParserTokenStream` created? (e.g., `CSSParserTokenStream stream("...")`)
    * **Key Methods:** What methods of `CSSParserTokenStream` are being called? (`Peek()`, `Consume()`, `AtEnd()`, `Offset()`, `SkipUntilPeekedTypeIs()`, `Save()`, `Restore()`, etc.)
    * **Assertions:** What is being asserted using `EXPECT_TRUE`, `EXPECT_EQ`, `EXPECT_FALSE`? This tells you what the expected behavior is.

6. **Connect Tests to Concepts:** As you understand the individual tests, connect them back to broader concepts:
    * **Basic Stream Operations:** `EmptyStream`, `PeekThenConsume`, `ConsumeThenPeek`, `ConsumeMultipleTokens` test the fundamental ways to interact with the token stream.
    * **Whitespace Handling:** `ConsumeWhitespace`, `ConsumeIncludingWhitespace` specifically test how whitespace is treated.
    * **Error Handling/Block Management:** `BlockErrorRecoveryConsumesRestOfBlock`, `BlockErrorRecoveryOnSuccess`, `BlockGuard` highlight how the class handles blocks (like `{}`) and potential errors within them.
    * **Lookahead:** `OffsetAfterPeek`, `OffsetAfterConsumes`, `LookAheadOffset`, `EnsureLookAhead` demonstrate the ability to peek at future tokens without consuming them.
    * **Skipping:** `SkipUntilPeekedTypeOffset` tests the ability to move through the stream efficiently.
    * **Boundaries:** `Boundary`, `MultipleBoundaries`, `IneffectiveBoundary`, `BoundaryBlockGuard`, `BoundaryRestoringBlockGuard` introduce the concept of setting limits for parsing.
    * **Save and Restore:** `SavePointRestoreWithoutLookahead` tests the ability to save and revert the stream's state.
    * **Restarting:** The `RestartTest`, `BoundaryRestartTest`, and `NullRestartTest` suites explore complex scenarios of restarting the tokenization process at specific points.

7. **Relate to Web Technologies (CSS, HTML, JavaScript):** Once you understand the functionality, think about how it relates to the web:
    * **CSS Parsing:** The most direct connection is CSS parsing. This class is a fundamental building block for turning CSS text into a structured representation. Give concrete examples of CSS syntax and how the methods would operate on them.
    * **HTML:** While not directly parsing HTML, CSS is embedded in HTML. The parser needs to handle CSS within `<style>` tags or inline styles. Consider scenarios where HTML structure might influence CSS parsing (though this class likely focuses solely on the CSS).
    * **JavaScript:** JavaScript interacts with CSS through the DOM (Document Object Model) and CSSOM (CSS Object Model). The output of this parser is used to build the CSSOM, which JavaScript can then manipulate.

8. **Infer Potential Usage Errors:** Based on how the class is designed, think about common mistakes a developer might make:
    * **Incorrectly Handling `AtEnd()`:**  Trying to consume tokens after reaching the end.
    * **Mismatched Block Handling:** Issues with nested blocks and ensuring they are correctly closed.
    * **Incorrect Use of Save/Restore:**  Not understanding the implications of saving and restoring the stream's state.
    * **Boundary Issues:** Setting boundaries incorrectly and being surprised by where the parser stops.

9. **Trace User Actions (Debugging):** Imagine how a user interaction might lead to this code being executed. Think about the browser's rendering pipeline:
    * User types CSS in a `<style>` tag or an external stylesheet.
    * The browser fetches and reads this CSS.
    * The CSS parser (using `CSSParserTokenStream`) tokenizes the CSS.
    * The tokens are used to build the CSSOM.
    * The browser uses the CSSOM to style the HTML content. Consider how errors in the CSS could lead to issues that a developer would debug, potentially stepping through this code.

10. **Hypothesize Inputs and Outputs:** For key methods or test cases, invent concrete examples:
    * **`Peek()`:** Input: `"color: red;"`. Output: Token representing "color".
    * **`Consume()`:** Input: `"color: red;"`. First call: Token "color", Second call: Token ":".
    * **`SkipUntilPeekedTypeIs<kSemicolonToken>()`:** Input: `"margin-left: 10px; padding: 5px;"` (when `Peek()` is on "margin-left"). Output: The stream's current token will be the semicolon after "10px".

11. **Refine and Organize:** Review your findings and organize them logically. Group related functionalities together. Use clear and concise language. Provide specific examples to illustrate your points. Use headings and bullet points for readability.

This systematic approach, moving from high-level understanding to detailed analysis of individual components and then connecting them back to the broader context, is crucial for effectively analyzing and explaining source code.
这个文件 `css_parser_token_stream_test.cc` 是 Chromium Blink 引擎中用于测试 `CSSParserTokenStream` 类的单元测试文件。它的主要功能是：

**1. 测试 `CSSParserTokenStream` 类的各种方法和行为。**

   `CSSParserTokenStream` 类负责将 CSS 字符串转换为一系列的 Token，并提供按顺序访问这些 Token 的接口。这个测试文件通过各种测试用例，验证了 `CSSParserTokenStream` 的核心功能是否正常工作。

**2. 涵盖 `CSSParserTokenStream` 的各种场景。**

   测试用例涵盖了空流、单个 Token、多个 Token、空白符处理、块（例如 `{}`, `()`）的处理、错误恢复、偏移量跟踪、向前看 (lookahead)、跳过 Token、边界 (boundary) 管理、保存点 (save point) 和恢复 (restore) 等多种场景。

**3. 使用 Google Test 框架进行测试。**

   该文件使用了 `testing/gtest/include/gtest/gtest.h`，表明它采用了 Google Test 框架来编写和执行测试用例。每个 `TEST` 宏定义了一个独立的测试用例，用于验证特定的功能。

**与 JavaScript, HTML, CSS 的功能关系：**

`CSSParserTokenStream` 是 CSS 解析过程中的一个关键组件，因此它与 CSS 的功能关系最为密切，同时也间接地与 HTML 和 JavaScript 有关。

* **CSS:**
    * **举例说明:**  `CSSParserTokenStream` 的输入是 CSS 字符串，例如 `"body { color: red; }" `。测试用例会验证它能否正确地将这个字符串分解成 `IDENT("body")`, `WHITESPACE`, `LEFT_BRACE`, `WHITESPACE`, `IDENT("color")`, `COLON`, `WHITESPACE`, `IDENT("red")`, `SEMICOLON`, `WHITESPACE`, `RIGHT_BRACE` 等 Token。
    * **假设输入与输出:**
        * **假设输入:** CSS 字符串 `" .class-name { font-size: 16px; } "`
        * **预期输出:** 一系列 `CSSParserToken` 对象，包括 `WHITESPACE`, `DELIM('.')`, `IDENT("class-name")`, `WHITESPACE`, `LEFT_BRACE`, `WHITESPACE`, `IDENT("font-size")`, `COLON`, `WHITESPACE`, `DIMENSION("16px")`, `SEMICOLON`, `WHITESPACE`, `RIGHT_BRACE`。

* **HTML:**
    * **举例说明:** 当浏览器解析 HTML 文件时，如果遇到 `<style>` 标签或者元素的 `style` 属性，会提取其中的 CSS 代码。这个 CSS 代码会被传递给 CSS 解析器，而 `CSSParserTokenStream` 就是 CSS 解析器的第一步，负责将 CSS 文本流转换为 Token 流。
    * **用户操作:** 用户在 HTML 文件中编写如下代码：
      ```html
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body {
            color: blue;
          }
        </style>
      </head>
      <body>
        <p>Hello, world!</p>
      </body>
      </html>
      ```
      当浏览器加载这个 HTML 文件时，`<style>` 标签内的 CSS 代码 `"body { color: blue; }"` 会被提取出来，并被 `CSSParserTokenStream` 处理。

* **JavaScript:**
    * **举例说明:** JavaScript 可以通过 DOM API (例如 `document.querySelector` 和元素的 `style` 属性) 来获取和修改元素的样式。浏览器内部会将 CSS 解析成一种内部表示（CSSOM - CSS Object Model），而 `CSSParserTokenStream` 是构建这个 CSSOM 的基础。JavaScript 对 CSS 的操作最终依赖于浏览器对 CSS 的解析结果。
    * **用户操作:** 用户编写 JavaScript 代码来修改页面元素的样式：
      ```javascript
      const paragraph = document.querySelector('p');
      paragraph.style.color = 'red';
      ```
      虽然 `CSSParserTokenStream` 不直接参与 JavaScript 的执行，但它负责了 CSS 解析的第一步，确保浏览器能正确理解 JavaScript 代码中引用的 CSS 属性和值。

**逻辑推理的假设输入与输出：**

* **假设输入:** `CSSParserTokenStream stream("  width : 100px  ");`
* **预期输出:**
    * `stream.Peek().GetType()` 在初始状态应该返回 `kWhitespaceToken`。
    * `ConsumeInTest(stream).GetType()` 应该返回 `kWhitespaceToken`。
    * 再次 `stream.Peek().GetType()` 应该返回 `kIdentToken` (值为 "width")。
    * `ConsumeInTest(stream).GetType()` 应该返回 `kIdentToken`。
    * 接下来会遇到 `kWhitespaceToken`, `kColonToken`, `kWhitespaceToken`, `kDimensionToken` (值为 "100px"), `kWhitespaceToken`, `kEOFToken`。

**涉及用户或者编程常见的使用错误：**

* **在 `AtEnd()` 返回 true 后仍然尝试 `Consume()` 或 `Peek()`:**  这会导致未定义的行为或断言失败。测试用例 `TEST(CSSParserTokenStreamTest, EmptyStream)` 验证了在空流上的操作。
    * **用户操作:**  如果 CSS 解析器代码没有正确检查是否已经到达流的末尾，就可能会发生这种情况。
    * **调试线索:** 当调试器停在 `ConsumeInTest(stream)` 或 `stream.Peek()` 并且 `stream.AtEnd()` 返回 `true` 时，就表明发生了这个错误。

* **错误地假设 `ConsumeIncludingWhitespace()` 会跳过所有空白符:**  `ConsumeIncludingWhitespace()` 只会跳过 *当前* Token 是空白符的情况。如果当前 Token 不是空白符，它会直接返回当前 Token。
    * **用户操作:** 开发者可能期望 `ConsumeIncludingWhitespace()` 能一次性跳过多个连续的空白符，但实际并非如此。
    * **调试线索:**  如果解析器在遇到非空白符后，仍然有空白符没有被处理，可能是错误地使用了 `ConsumeIncludingWhitespace()`。

* **忘记正确管理 `BlockGuard` 的生命周期:**  `BlockGuard` 用于处理块的开始和结束。如果 `BlockGuard` 没有正确地析构，可能会导致流的状态不正确。
    * **用户操作:**  在解析 CSS 块结构（例如规则集、媒体查询）时，如果 `BlockGuard` 的使用不当，可能会导致解析提前结束或进入错误的状态。
    * **调试线索:**  如果在解析块结构时出现意外的结束或 Token 类型错误，可能需要检查 `BlockGuard` 的创建和销毁是否匹配。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中访问一个网页。**
2. **浏览器开始解析 HTML 代码。**
3. **浏览器遇到 `<style>` 标签或者带有 `style` 属性的元素。**
4. **浏览器提取出 CSS 代码。**
5. **CSS 解析器开始工作，`CSSParserTokenStream` 作为第一步，接收 CSS 字符串作为输入。**
6. **`CSSParserTokenStream` 将 CSS 字符串分解成一系列的 Token。**
7. **如果 CSS 代码存在语法错误，或者解析器的逻辑有 bug，`CSSParserTokenStream` 可能会产生错误的 Token 流。**
8. **作为开发者，为了调试 CSS 解析过程中的问题，可能会需要查看 `CSSParserTokenStream` 的行为。**
9. **调试时，开发者可能会设置断点在 `css_parser_token_stream_test.cc` 中的测试用例中，或者在实际的 CSS 解析代码中调用 `CSSParserTokenStream` 的地方。**
10. **通过单步执行代码，查看 `Peek()`, `Consume()`, `AtEnd()` 等方法的返回值，以及 `Offset()` 的变化，来理解 Token 流的状态。**
11. **如果遇到意外的 Token 类型或顺序，开发者可以参考 `css_parser_token_stream_test.cc` 中的测试用例，来理解预期的行为，从而找到代码中的错误。**
12. **例如，如果解析器在遇到一个冒号后，期望下一个 Token 是一个值，但实际却遇到了一个分号，开发者可以检查 `SkipUntilPeekedTypeIs<kSemicolonToken>()` 是否被错误地调用，或者是否在应该调用 `Consume()` 的地方遗漏了。**

总而言之，`css_parser_token_stream_test.cc` 是一个至关重要的测试文件，它确保了 Blink 引擎能够正确地将 CSS 文本转换为可供后续处理的 Token 流，这对于网页的正确渲染至关重要。当 CSS 解析出现问题时，这个文件中的测试用例可以作为理解和调试问题的起点。

### 提示词
```
这是目录为blink/renderer/core/css/parser/css_parser_token_stream_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/parser/css_parser_token_stream.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_save_point.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

// Avoids the DCHECK that we've Peek()-ed before.
const CSSParserToken& ConsumeInTest(CSSParserTokenStream& stream) {
  stream.Peek();
  return stream.Consume();
}

CSSParserToken ConsumeIncludingWhitespaceInTest(CSSParserTokenStream& stream) {
  stream.Peek();
  return stream.ConsumeIncludingWhitespace();
}

String GetUntilEndOfBlock(CSSParserTokenStream& stream) {
  StringBuilder sb;
  while (!stream.AtEnd()) {
    ConsumeInTest(stream).Serialize(sb);
  }
  return sb.ReleaseString();
}

String SerializeTokens(const Vector<CSSParserToken, 32>& tokens) {
  StringBuilder sb;
  for (const CSSParserToken& token : tokens) {
    token.Serialize(sb);
  }
  return sb.ReleaseString();
}

TEST(CSSParserTokenStreamTest, EmptyStream) {
  CSSParserTokenStream stream("");
  EXPECT_TRUE(ConsumeInTest(stream).IsEOF());
  EXPECT_TRUE(stream.Peek().IsEOF());
  EXPECT_TRUE(stream.AtEnd());
}

TEST(CSSParserTokenStreamTest, PeekThenConsume) {
  CSSParserTokenStream stream("A");  // kIdent
  EXPECT_EQ(kIdentToken, stream.Peek().GetType());
  EXPECT_EQ(kIdentToken, ConsumeInTest(stream).GetType());
  EXPECT_TRUE(stream.AtEnd());
}

TEST(CSSParserTokenStreamTest, ConsumeThenPeek) {
  CSSParserTokenStream stream("A");  // kIdent
  EXPECT_EQ(kIdentToken, ConsumeInTest(stream).GetType());
  EXPECT_TRUE(stream.AtEnd());
}

TEST(CSSParserTokenStreamTest, ConsumeMultipleTokens) {
  CSSParserTokenStream stream("A 1");  // kIdent kWhitespace kNumber
  EXPECT_EQ(kIdentToken, ConsumeInTest(stream).GetType());
  EXPECT_EQ(kWhitespaceToken, ConsumeInTest(stream).GetType());
  EXPECT_EQ(kNumberToken, ConsumeInTest(stream).GetType());
  EXPECT_TRUE(stream.AtEnd());
}

TEST(CSSParserTokenStreamTest, UncheckedPeekAndConsumeAfterPeek) {
  CSSParserTokenStream stream("A");  // kIdent
  EXPECT_EQ(kIdentToken, stream.Peek().GetType());
  EXPECT_EQ(kIdentToken, stream.UncheckedPeek().GetType());
  EXPECT_EQ(kIdentToken, stream.UncheckedConsume().GetType());
  EXPECT_TRUE(stream.AtEnd());
}

TEST(CSSParserTokenStreamTest, UncheckedPeekAndConsumeAfterAtEnd) {
  CSSParserTokenStream stream("A");  // kIdent
  EXPECT_FALSE(stream.AtEnd());
  EXPECT_EQ(kIdentToken, stream.UncheckedPeek().GetType());
  EXPECT_EQ(kIdentToken, stream.UncheckedConsume().GetType());
  EXPECT_TRUE(stream.AtEnd());
}

TEST(CSSParserTokenStreamTest, ConsumeWhitespace) {
  CSSParserTokenStream stream(" \t\n");  // kWhitespace

  EXPECT_EQ(kWhitespaceToken, ConsumeInTest(stream).GetType());
  EXPECT_TRUE(stream.AtEnd());
}

TEST(CSSParserTokenStreamTest, ConsumeIncludingWhitespace) {
  CSSParserTokenStream stream("A \t\n");  // kIdent kWhitespace

  EXPECT_EQ(kIdentToken, ConsumeIncludingWhitespaceInTest(stream).GetType());
  EXPECT_TRUE(stream.AtEnd());
}

TEST(CSSParserTokenStreamTest, BlockErrorRecoveryConsumesRestOfBlock) {
  CSSParserTokenStream stream("{B }1");

  {
    CSSParserTokenStream::BlockGuard guard(stream);
    EXPECT_EQ(kIdentToken, ConsumeInTest(stream).GetType());
    EXPECT_FALSE(stream.AtEnd());
  }  // calls destructor

  EXPECT_EQ(kNumberToken, ConsumeInTest(stream).GetType());
}

TEST(CSSParserTokenStreamTest, BlockErrorRecoveryOnSuccess) {
  CSSParserTokenStream stream("{B }1");

  {
    CSSParserTokenStream::BlockGuard guard(stream);
    EXPECT_EQ(kIdentToken, ConsumeInTest(stream).GetType());
    EXPECT_EQ(kWhitespaceToken, ConsumeInTest(stream).GetType());
    EXPECT_TRUE(stream.AtEnd());
  }  // calls destructor

  EXPECT_EQ(kNumberToken, ConsumeInTest(stream).GetType());
}

TEST(CSSParserTokenStreamTest, OffsetAfterPeek) {
  CSSParserTokenStream stream("ABC");

  EXPECT_EQ(0U, stream.Offset());
  EXPECT_EQ(kIdentToken, stream.Peek().GetType());
  EXPECT_EQ(0U, stream.Offset());
}

TEST(CSSParserTokenStreamTest, OffsetAfterConsumes) {
  CSSParserTokenStream stream("ABC 1 {23 }");

  EXPECT_EQ(0U, stream.Offset());
  EXPECT_EQ(kIdentToken, ConsumeInTest(stream).GetType());
  EXPECT_EQ(3U, stream.Offset());
  EXPECT_EQ(kWhitespaceToken, ConsumeInTest(stream).GetType());
  EXPECT_EQ(4U, stream.Offset());
  EXPECT_EQ(kNumberToken, ConsumeIncludingWhitespaceInTest(stream).GetType());
  EXPECT_EQ(6U, stream.Offset());
}

TEST(CSSParserTokenStreamTest, LookAheadOffset) {
  CSSParserTokenStream stream("ABC/* *//* */1");

  stream.EnsureLookAhead();
  EXPECT_EQ(0U, stream.Offset());
  EXPECT_EQ(0U, stream.LookAheadOffset());
  EXPECT_EQ(kIdentToken, ConsumeInTest(stream).GetType());

  stream.EnsureLookAhead();
  EXPECT_EQ(3U, stream.Offset());
  EXPECT_EQ(13U, stream.LookAheadOffset());
}

TEST(CSSParserTokenStreamTest, SkipUntilPeekedTypeOffset) {
  CSSParserTokenStream stream("a b c;d e f");

  // a
  EXPECT_EQ(kIdentToken, stream.Peek().GetType());
  EXPECT_EQ(0u, stream.Offset());

  stream.SkipUntilPeekedTypeIs<kSemicolonToken>();
  EXPECT_EQ(kSemicolonToken, stream.Peek().GetType());
  EXPECT_EQ(5u, stream.Offset());

  // Again, when we're already at kSemicolonToken.
  stream.SkipUntilPeekedTypeIs<kSemicolonToken>();
  EXPECT_EQ(kSemicolonToken, stream.Peek().GetType());
  EXPECT_EQ(5u, stream.Offset());
}

TEST(CSSParserTokenStreamTest, SkipUntilPeekedTypeOffsetEndOfFile) {
  CSSParserTokenStream stream("a b c");

  // a
  EXPECT_EQ(kIdentToken, stream.Peek().GetType());
  EXPECT_EQ(0u, stream.Offset());

  stream.SkipUntilPeekedTypeIs<kSemicolonToken>();
  EXPECT_TRUE(stream.AtEnd());
  EXPECT_EQ(5u, stream.Offset());

  // Again, when we're already at EOF.
  stream.SkipUntilPeekedTypeIs<kSemicolonToken>();
  EXPECT_TRUE(stream.AtEnd());
  EXPECT_EQ(5u, stream.Offset());
}

TEST(CSSParserTokenStreamTest, SkipUntilPeekedTypeOffsetEndOfBlock) {
  CSSParserTokenStream stream("a { a b c } d ;");

  // a
  EXPECT_EQ(0u, stream.Offset());
  EXPECT_EQ(kIdentToken, ConsumeInTest(stream).GetType());

  EXPECT_EQ(1u, stream.Offset());
  EXPECT_EQ(kWhitespaceToken, ConsumeInTest(stream).GetType());

  EXPECT_EQ(kLeftBraceToken, stream.Peek().GetType());
  EXPECT_EQ(2u, stream.Offset());

  {
    CSSParserTokenStream::BlockGuard guard(stream);

    EXPECT_EQ(kWhitespaceToken, stream.Peek().GetType());
    EXPECT_EQ(3u, stream.Offset());

    stream.SkipUntilPeekedTypeIs<kSemicolonToken>();
    EXPECT_TRUE(stream.AtEnd());  // End of block.
    EXPECT_EQ(kRightBraceToken, stream.UncheckedPeek().GetType());
    EXPECT_EQ(10u, stream.Offset());

    // Again, when we're already at the end-of-block.
    stream.SkipUntilPeekedTypeIs<kSemicolonToken>();
    EXPECT_TRUE(stream.AtEnd());  // End of block.
    EXPECT_EQ(kRightBraceToken, stream.UncheckedPeek().GetType());
    EXPECT_EQ(10u, stream.Offset());
  }

  EXPECT_EQ(kWhitespaceToken, stream.Peek().GetType());
  EXPECT_EQ(11u, stream.Offset());
}

TEST(CSSParserTokenStreamTest, SkipUntilPeekedTypeIsEmpty) {
  CSSParserTokenStream stream("{23 }");

  stream.SkipUntilPeekedTypeIs<>();
  EXPECT_TRUE(stream.AtEnd());
}

TEST(CSSParserTokenStreamTest, Boundary) {
  CSSParserTokenStream stream("foo:red;bar:blue;asdf");

  {
    CSSParserTokenStream::Boundary boundary(stream, kSemicolonToken);
    stream.SkipUntilPeekedTypeIs<>();
    EXPECT_TRUE(stream.AtEnd());
  }

  EXPECT_FALSE(stream.AtEnd());
  EXPECT_EQ(kSemicolonToken, ConsumeInTest(stream).GetType());

  {
    CSSParserTokenStream::Boundary boundary(stream, kSemicolonToken);
    stream.SkipUntilPeekedTypeIs<>();
    EXPECT_TRUE(stream.AtEnd());
  }

  EXPECT_FALSE(stream.AtEnd());
  EXPECT_EQ(kSemicolonToken, ConsumeInTest(stream).GetType());

  EXPECT_EQ("asdf", ConsumeInTest(stream).Value());
  EXPECT_TRUE(stream.AtEnd());
}

TEST(CSSParserTokenStreamTest, MultipleBoundaries) {
  CSSParserTokenStream stream("a:b,c;d:,;e");

  {
    CSSParserTokenStream::Boundary boundary_semicolon(stream, kSemicolonToken);

    {
      CSSParserTokenStream::Boundary boundary_comma(stream, kCommaToken);

      {
        CSSParserTokenStream::Boundary boundary_colon(stream, kColonToken);
        stream.SkipUntilPeekedTypeIs<>();
        EXPECT_TRUE(stream.AtEnd());
      }

      EXPECT_FALSE(stream.AtEnd());
      EXPECT_EQ(kColonToken, ConsumeInTest(stream).GetType());

      stream.SkipUntilPeekedTypeIs<>();
      EXPECT_TRUE(stream.AtEnd());
    }

    EXPECT_FALSE(stream.AtEnd());
    EXPECT_EQ(kCommaToken, ConsumeInTest(stream).GetType());

    stream.SkipUntilPeekedTypeIs<>();
    EXPECT_TRUE(stream.AtEnd());
  }

  EXPECT_FALSE(stream.AtEnd());
  EXPECT_EQ(kSemicolonToken, ConsumeInTest(stream).GetType());

  stream.SkipUntilPeekedTypeIs<>();
  EXPECT_TRUE(stream.AtEnd());
}

TEST(CSSParserTokenStreamTest, IneffectiveBoundary) {
  CSSParserTokenStream stream("a:b|");

  {
    CSSParserTokenStream::Boundary boundary_colon(stream, kColonToken);

    {
      // It's valid to add another boundary, but it has no affect in this
      // case, since kColonToken appears first.
      CSSParserTokenStream::Boundary boundary_semicolon(stream,
                                                        kSemicolonToken);

      stream.SkipUntilPeekedTypeIs<>();

      EXPECT_EQ(kColonToken, stream.Peek().GetType());
      EXPECT_TRUE(stream.AtEnd());
    }

    EXPECT_TRUE(stream.AtEnd());
  }

  EXPECT_FALSE(stream.AtEnd());
}

TEST(CSSParserTokenStreamTest, BoundaryBlockGuard) {
  CSSParserTokenStream stream("a[b;c]d;e");

  {
    CSSParserTokenStream::Boundary boundary(stream, kSemicolonToken);
    EXPECT_EQ("a", ConsumeInTest(stream).Value());

    {
      CSSParserTokenStream::BlockGuard guard(stream);
      // The boundary does not apply within blocks.
      EXPECT_EQ("b;c", GetUntilEndOfBlock(stream));
    }

    // However, now the boundary should apply.
    EXPECT_EQ("d", GetUntilEndOfBlock(stream));
  }
}

TEST(CSSParserTokenStreamTest, BoundaryRestoringBlockGuard) {
  CSSParserTokenStream stream("a[b;c]d;e");

  {
    CSSParserTokenStream::Boundary boundary(stream, kSemicolonToken);
    EXPECT_EQ("a", ConsumeInTest(stream).Value());

    {
      stream.EnsureLookAhead();
      CSSParserTokenStream::RestoringBlockGuard guard(stream);
      // The boundary does not apply within blocks.
      EXPECT_EQ("b;c", GetUntilEndOfBlock(stream));
      EXPECT_TRUE(guard.Release());
    }

    // However, now the boundary should apply.
    EXPECT_EQ("d", GetUntilEndOfBlock(stream));
  }
}

TEST(CSSParserTokenStreamTest, SavePointRestoreWithoutLookahead) {
  CSSParserTokenStream stream("a b c");
  stream.EnsureLookAhead();

  {
    CSSParserSavePoint savepoint(stream);
    stream.Peek();
    stream.UncheckedConsume();  // a
    stream.EnsureLookAhead();
    stream.Peek();
    stream.UncheckedConsume();  // whitespace

    EXPECT_FALSE(stream.HasLookAhead());
    // Let `savepoint` go out of scope without being released.
  }

  // We should have restored to the beginning.
  EXPECT_EQ("a", stream.Peek().Value());
}

namespace {

Vector<CSSParserToken, 32> TokenizeAll(String string) {
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

// See struct RestartData.
std::pair<wtf_size_t, wtf_size_t> ParseRestart(String restart) {
  wtf_size_t restart_target = restart.find('^');
  wtf_size_t restart_offset = restart.find('<');
  return std::make_pair(restart_target, restart_offset);
}

// Consume all tokens in `stream`, and store them in `tokens`,
// restarting (once) at the token with offset `restart_offset`
// to the offset specified by `restart_target`.
void TokenizeInto(CSSParserTokenStream& stream,
                  wtf_size_t restart_target,
                  wtf_size_t restart_offset,
                  Vector<CSSParserToken, 32>& tokens) {
  std::optional<CSSParserTokenStream::State> saved_state;

  while (true) {
    stream.EnsureLookAhead();

    if (restart_target == stream.Offset()) {
      saved_state = stream.Save();
    }

    if (saved_state.has_value() && restart_offset == stream.Offset()) {
      stream.Restore(saved_state.value());
      saved_state.reset();
      // Do not restart again:
      restart_target = std::numeric_limits<wtf_size_t>::max();
      continue;
    }

    if (stream.AtEnd()) {
      return;
    }

    if (stream.UncheckedPeek().GetBlockType() == CSSParserToken::kBlockStart) {
      // Push block-start token about to be consumed by BlockGuard.
      tokens.push_back(stream.UncheckedPeek());
      CSSParserTokenStream::BlockGuard guard(stream);
      TokenizeInto(stream, restart_target, restart_offset, tokens);
      // Note that stream.AtEnd() is true for EOF, but also for
      // any block-end token.
      stream.EnsureLookAhead();
      DCHECK(stream.AtEnd());
      if (stream.UncheckedPeek().GetType() != kEOFToken) {
        // Add block-end token.
        tokens.push_back(stream.UncheckedPeek());
      }
    } else {
      tokens.push_back(stream.UncheckedConsume());
    }
  }
}

}  // namespace

struct RestartData {
  // The string to tokenize.
  const char* input;
  // Specifies where to restart from and to as follows:
  //
  // '^' - Restart to this offset.
  // '<' - Instead of consuming the token at this offset, restart to the
  //       offset indicated '^' instead.
  //
  // Example:
  //
  //  Input:   "foo bar baz"
  //  Restart: "    ^   <  "
  //
  // The above will consume foo, <space>, <bar>, <space>, then restart
  // at bar.
  //
  // Note that the '<' can appear at an offset equal to the length of the
  // input string, to represent restarts that happen when the stream is
  // at EOF.
  const char* restart;
  // Represents the expected token sequence, including the restart.
  // Continuing the example above, the appropriate 'ref' would be:
  //
  //  "foo bar bar baz"
  const char* ref;
};

RestartData restart_data[] = {
    // clang-format off
    {
      "x y z",
      "^ <  ",
      "x x y z"
    },
    {
      "x y z",
      "  ^ <",
      "x y y z"
    },
    {
      "x y z",
      "   ^<",
      "x y /**/ z"
    },
    {
      "x y z",
      "^<   ",
      "x/**/x y z"
    },
    {
      "x y z",
      "^  <",
      "x y/**/x y z"
    },

    // Restarting on block-start:
    {
      "x y { a b c } z",
      "  ^ <          ",
      "x y y { a b c } z"
    },
    {
      "x y ( a b c ) z",
      "  ^ <          ",
      "x y y ( a b c ) z"
    },
    {
      "x y { a b c } z",
      "  ^ <          ",
      "x y y { a b c } z"
    },
    {
      "x y foo( a b c ) z",
      "  ^ <          ",
      "x y y foo( a b c ) z"
    },

    // Restarting over a block:
    {
      "x y { a b c } z w",
      "  ^           <  ",
      "x y { a b c } y { a b c } z w"
    },
    {
      "x y { a b c } z w",
      "  ^          <   ",
      "x y { a b c }y { a b c } z w"
    },
    // Restart to block-start:
    {
      "x y { a b c } z w",
      "    ^         <   ",
      "x y { a b c } { a b c } z w"
    },

    // Restarting over an EOF-terminated block
    {
      "x y { a b c ",
      "  ^         <",
      "x y { a b c y { a b c "
    },

    // Restart within block:
    {
      "x y { a b c } z",
      "      ^   <    ",
      "x y { a b a b c } z"
    },
    {
      "x y { a b c } z",
      "     ^     <   ",
      "x y { a b c a b c } z"
    },
    {
      "x y { a b c } z",
      "     ^      <  ",
      "x y { a b c /**/ a b c } z"
    },
    // Restart within EOF-terminated block.
    {
      "x y {([ a b c d",
      "        ^   <  ",
      "x y {([ a b a b c d"
    },
    {
      "x y {([ a b c d",
      "        ^     <",
      "x y {([ a b c a b c d"
    },

    // clang-format on
};

class RestartTest : public testing::Test,
                    public testing::WithParamInterface<RestartData> {};

INSTANTIATE_TEST_SUITE_P(CSSParserTokenStreamTest,
                         RestartTest,
                         testing::ValuesIn(restart_data));

TEST_P(RestartTest, All) {
  RestartData param = GetParam();

  String ref(param.ref);
  Vector<CSSParserToken, 32> ref_tokens = TokenizeAll(ref);

  String input(param.input);
  CSSParserTokenStream stream(input);

  auto [restart_target, restart_offset] = ParseRestart(param.restart);
  Vector<CSSParserToken, 32> actual_tokens;
  TokenizeInto(stream, restart_target, restart_offset, actual_tokens);

  SCOPED_TRACE(testing::Message()
               << "Expected (serialized): " << SerializeTokens(ref_tokens));
  SCOPED_TRACE(testing::Message()
               << "Actual (serialized): " << SerializeTokens(actual_tokens));

  SCOPED_TRACE(param.ref);
  SCOPED_TRACE(param.restart);
  SCOPED_TRACE(param.input);

  EXPECT_EQ(actual_tokens, ref_tokens);
}

// Same as RestartTest, except performs all restarts during a boundary.
class BoundaryRestartTest : public testing::Test,
                            public testing::WithParamInterface<RestartData> {};

INSTANTIATE_TEST_SUITE_P(CSSParserTokenStreamTest,
                         BoundaryRestartTest,
                         testing::ValuesIn(restart_data));

TEST_P(BoundaryRestartTest, All) {
  RestartData param = GetParam();

  String ref(param.ref);
  Vector<CSSParserToken, 32> ref_tokens = TokenizeAll(ref);

  String input(param.input);
  CSSParserTokenStream stream(input);

  CSSParserTokenStream::Boundary boundary(stream, kSemicolonToken);

  auto [restart_target, restart_offset] = ParseRestart(param.restart);
  Vector<CSSParserToken, 32> actual_tokens;
  TokenizeInto(stream, restart_target, restart_offset, actual_tokens);

  SCOPED_TRACE(testing::Message()
               << "Expected (serialized): " << SerializeTokens(ref_tokens));
  SCOPED_TRACE(testing::Message()
               << "Actual (serialized): " << SerializeTokens(actual_tokens));

  SCOPED_TRACE(param.ref);
  SCOPED_TRACE(param.restart);
  SCOPED_TRACE(param.input);

  EXPECT_EQ(actual_tokens, ref_tokens);
}

class NullRestartTest : public testing::Test,
                        public testing::WithParamInterface<RestartData> {};

INSTANTIATE_TEST_SUITE_P(CSSParserTokenStreamTest,
                         NullRestartTest,
                         testing::ValuesIn(restart_data));

// Ignores RestartData.restart, and instead tests restarting to and from
// the same offset, i.e. "restarting" to the offset we're already on.
TEST_P(NullRestartTest, All) {
  RestartData param = GetParam();

  String input(param.input);
  Vector<CSSParserToken, 32> ref_tokens = TokenizeAll(input);

  for (wtf_size_t restart_offset = 0; restart_offset <= input.length();
       ++restart_offset) {
    CSSParserTokenStream stream(input);

    Vector<CSSParserToken, 32> actual_tokens;
    TokenizeInto(stream, /* restart_target */ restart_offset, restart_offset,
                 actual_tokens);

    SCOPED_TRACE(testing::Message()
                 << "Expected (serialized): " << SerializeTokens(ref_tokens));
    SCOPED_TRACE(testing::Message()
                 << "Actual (serialized): " << SerializeTokens(actual_tokens));

    SCOPED_TRACE(param.input);
    SCOPED_TRACE(testing::Message() << "restart_offset:" << restart_offset);

    EXPECT_EQ(actual_tokens, ref_tokens);
  }
}

class TestStream {
  STACK_ALLOCATED();

 public:
  explicit TestStream(String input) : input_(input), stream_(input) {
    stream_.EnsureLookAhead();
  }

  void EnsureLookahead() { stream_.EnsureLookAhead(); }

  const CSSParserToken& Peek() { return stream_.Peek(); }

  bool AtEnd() { return stream_.AtEnd(); }

  bool ConsumeTokens(String expected) {
    CSSTokenizer tokenizer(expected);
    while (true) {
      CSSParserToken expected_token = tokenizer.TokenizeSingle();
      if (expected_token.GetType() == kEOFToken) {
        break;
      }
      if (stream_.Peek() != expected_token) {
        return false;
      }
      stream_.Consume();
    }
    return true;
  }

  CSSParserTokenStream::State Save() {
    stream_.EnsureLookAhead();
    return stream_.Save();
  }

 private:
  friend class TestRestoringBlockGuard;
  friend class TestBlockGuard;
  friend class TestBoundary;
  String input_;
  CSSParserTokenStream stream_;
};

// The following various Test* classes only exist to accept
// a TestStream instead of a CSSParserTokenStream.

class TestRestoringBlockGuard {
  STACK_ALLOCATED();

 public:
  explicit TestRestoringBlockGuard(TestStream& stream)
      : guard_(stream.stream_) {}
  bool Release() { return guard_.Release(); }

 private:
  CSSParserTokenStream::RestoringBlockGuard guard_;
};

class TestBlockGuard {
  STACK_ALLOCATED();

 public:
  explicit TestBlockGuard(TestStream& stream) : guard_(stream.stream_) {}

 private:
  CSSParserTokenStream::BlockGuard guard_;
};

class TestBoundary {
  STACK_ALLOCATED();

 public:
  explicit TestBoundary(TestStream& stream, CSSParserTokenType boundary_type)
      : boundary_(stream.stream_, boundary_type) {}

 private:
  CSSParserTokenStream::Boundary boundary_;
};

class RestoringBlockGuardTest : public testing::Test {};

TEST_F(RestoringBlockGuardTest, Restore) {
  TestStream stream("a b c (d e f) g h i");
  EXPECT_TRUE(stream.ConsumeTokens("a b c "));

  // Restore immediately after guard.
  {
    stream.EnsureLookahead();
    TestRestoringBlockGuard guard(stream);
  }
  EXPECT_EQ(kLeftParenthesisToken, stream.Peek().GetType());

  // Restore after consuming one token.
  {
    stream.EnsureLookahead();
    TestRestoringBlockGuard guard(stream);
    EXPECT_TRUE(stream.ConsumeTokens("d"));
  }
  EXPECT_EQ(kLeftParenthesisToken, stream.Peek().GetType());

  // Restore in the middle.
  {
    stream.EnsureLookahead();
    TestRestoringBlockGuard guard(stream);
    EXPECT_TRUE(stream.ConsumeTokens("d e"));
  }
  EXPECT_EQ(kLeftParenthesisToken, stream.Peek().GetType());

  // Restore with one token left.
  {
    stream.EnsureLookahead();
    TestRestoringBlockGuard guard(stream);
    EXPECT_TRUE(stream.ConsumeTokens("d e "));
  }
  EXPECT_EQ(kLeftParenthesisToken, stream.Peek().GetType());

  // Restore at the end (of the block).
  {
    stream.EnsureLookahead();
    TestRestoringBlockGuard guard(stream);
    EXPECT_TRUE(stream.ConsumeTokens("d e f"));
    EXPECT_TRUE(stream.AtEnd());
  }
  EXPECT_EQ(kLeftParenthesisToken, stream.Peek().GetType());
}

TEST_F(RestoringBlockGuardTest, NestedRestore) {
  TestStream stream("a b [c (d e f) g] h i");
  EXPECT_TRUE(stream.ConsumeTokens("a b "));

  // Restore immediately after inner guard.
  {
    stream.EnsureLookahead();
    TestRestoringBlockGuard outer_guard(stream);  // [
    EXPECT_TRUE(stream.ConsumeTokens("c "));
    {
      stream.EnsureLookahead();
      TestRestoringBlockGuard inner_guard(stream);  // (
    }
    EXPECT_EQ(kLeftParenthesisToken, stream.Peek().GetType());
  }
  EXPECT_EQ(kLeftBracketToken, stream.Peek().GetType());

  // Restore in the middle of inner block.
  {
    stream.EnsureLookahead();
    TestRestoringBlockGuard outer_guard(stream);  // [
    EXPECT_TRUE(stream.ConsumeTokens("c "));
    {
      stream.EnsureLookahead();
      TestRestoringBlockGuard inner_guard(stream);  // (
      EXPECT_TRUE(stream.ConsumeTokens("d "));
    }
    EXPECT_EQ(kLeftParenthesisToken, stream.Peek().GetType());
  }
  EXPECT_EQ(kLeftBracketToken, stream.Peek().GetType());

  // Restore at the end of inner block.
  {
    stream.EnsureLookahead();
    TestRestoringBlockGuard outer_guard(stream);  // [
    EXPECT_TRUE(stream.ConsumeTokens("c "));
    {
      stream.EnsureLookahead();
      TestRestoringBlockGuard inner_guard(stream);  // (
      EXPECT_TRUE(stream.ConsumeTokens("d e f"));
    }
    EXPECT_EQ(kLeftParenthesisToken, stream.Peek().GetType());
  }
  EXPECT_EQ(kLeftBracketToken, stream.Peek().GetType());
}

TEST_F(RestoringBlockGuardTest, Release) {
  TestStream stream("a b c (d e f) g h i");
  EXPECT_TRUE(stream.ConsumeTokens("a b c "));

  // Cannot release unless we're AtEnd.
  {
    stream.EnsureLookahead();
    TestRestoringBlockGuard guard(stream);
    EXPECT_FALSE(guard.Release());
    stream.ConsumeTokens("d");
    EXPECT_FALSE(guard.Release());
    stream.ConsumeTokens(" e ");
    EXPECT_FALSE(guard.Release());
    stream.ConsumeTokens("f");
  }
  EXPECT_EQ(kLeftParenthesisToken, stream.Peek().GetType());

  // Same again, except this time with a Release after consuming 'f'.
  {
    stream.EnsureLookahead();
    TestRestoringBlockGuard guard(stream);
    EXPECT_FALSE(guard.Release());
    stream.ConsumeTokens("d");
    EXPECT_FALSE(guard.Release());
    stream.ConsumeTokens(" e ");
    EXPECT_FALSE(guard.Release());
    stream.ConsumeTokens("f");
    EXPECT_TRUE(guard.Release());
  }
  EXPECT_TRUE(stream.ConsumeTokens(" g h i"));
}

TEST_F(RestoringBlockGuardTest, ReleaseEOF) {
  TestStream stream("a b c (d e f");
  EXPECT_TRUE(stream.ConsumeTokens("a b c "));

  {
    stream.EnsureLookahead();
    TestRestoringBlockGuard guard(stream);
    EXPECT_FALSE(guard.Release());
    stream.ConsumeTokens("d e f");
    EXPECT_TRUE(guard.Release());
  }

  EXPECT_TRUE(stream.Peek().IsEOF());
}

TEST_F(RestoringBlockGuardTest, NestedRelease) {
  TestStream stream("a b [c (d e f) g] h i");
  EXPECT_TRUE(stream.ConsumeTokens("a b "));

  // Inner guard released, but outer guard is not.
  {
    stream.EnsureLookahead();
    TestRestoringBlockGuard outer_guard(stream);  // [
    EXPECT_TRUE(stream.ConsumeTokens("c "));
    EXPECT_FALSE(outer_guard.Release());
    {
      stream.EnsureLookahead();
      TestRestoringBlockGuard inner_guard(stream);  // (
      EXPECT_FALSE(inner_guard.Release());
      EXPECT_TRUE(stream.ConsumeTokens("d e f"));
      EXPECT_TRUE(inner_guard.Release());
    }
    EXPECT_TRUE(stream.ConsumeTokens(" g"));
  }
  EXPECT_EQ(kLeftBracketToken, stream.Peek().GetType());

  // Both guards released.
  {
    stream.EnsureLookahead();
    TestRestoringBlockGuard outer_guard(stream);  // [
    EXPECT_TRUE(stream.ConsumeTokens("c "));
    EXPECT_FALSE(outer_guard.Release());
    {
      stream.EnsureLookahead();
      TestRestoringBlockGuard inner_guard(stream);  // (
      EXPECT_FALSE(inner_guard.Release());
      EXPECT_TRUE(stream.ConsumeTokens("d e f"));
      EXPECT_TRUE(inner_guard.Release());
    }
    EXPECT_FALSE(outer_guard.Release());
    EXPECT_TRUE(stream.ConsumeTokens(" g"));
    EXPECT_TRUE(outer_guard.Release());
  }
  EXPECT_TRUE(stream.ConsumeTokens(" h i"));
}

TEST_F(RestoringBlockGuardTest, ReleaseImmediate) {
  TestStream stream("a b (c d) e");
  EXPECT_TRUE(stream.ConsumeTokens("a b "));

  stream.EnsureLookahead();
  TestRestoringBlockGuard guard(stream);
  EXPECT_FALSE(guard.Release());
  EXPECT_TRUE(stream.ConsumeTokens("c d"));
  EXPECT_TRUE(guard.Release());
  // The above Release() call should consume the block-end,
  // even if RestoringBlockGuard hasn't gone out of scope.

  EXPECT_EQ(kWhitespaceToken, stream.Peek().GetType());
  EXPECT_TRUE(stream.ConsumeTokens(" e"));
  EXPECT_TRUE(stream.Peek().IsEOF());
}

TEST_F(RestoringBlockGuardTest, BlockStack) {
  TestStream stream("a (b c) d) e");
  EXPECT_TRUE(stream.ConsumeTokens("a "));

  // Start consuming the block, but abort (restart).
  {
    stream.EnsureLookahead();
    TestRestoringBlockGuard guard(stream);  // (
  }
  EXPECT_EQ(kLeftParenthesisToken, stream.Peek().GetType());

  // Now fully consume the block.
  {
    stream.EnsureLookahead();
    TestRestoringBlockGuard guard(stream);  // (
    EXPECT_TRUE(stream.ConsumeTokens("b c"));
    EXPECT_TRUE(guard.Release());
  }
  EXPECT_TRUE(stream.ConsumeTokens(" d"));

  // The restart should have adjusted the block stack, otherwise
  // the final ")" will incorrectly appear as kBlockEnd.
  EXPECT_EQ(stream.Peek().GetType(), kRightParenthesisToken);
  EXPECT_EQ(stream.Peek().GetBlockType(), CSSParserToken::kNotBlock);
}

TEST_F(RestoringBlockGuardTest, RestoreDuringBoundary) {
  TestStream stream("a (b c ; d e) f; g h");
  EXPECT_TRUE(stream.ConsumeTokens("a "));

  TestBoundary boundary(stream, kSemicolonToken);

  {
    stream.EnsureLookahead();
    TestRestoringBlockGuard guard(stream);
    // The outer boundary should not apply here, hence we should be able
    // to consume the inner kSemicolonToken.
    EXPECT_TRUE(stream.ConsumeTokens("b c ; d"));

    // We didn't consume everything in the block, so we should restore
    // `guard` goes out of scope.
  }

  EXPECT_EQ(kLeftParenthesisToken, stream.Peek().GetType());
  // Skip past the block.
  { TestBlockGuard block_guard(stream); }
  EXPECT_TRUE(stream.ConsumeTokens(" f"));

  // We're at the outer kSemicolonToken, which is considered to be AtEnd
  // due to the boundary.
  EXPECT_TRUE(stream.AtEnd());
}

}  // namespace

}  // namespace blink
```