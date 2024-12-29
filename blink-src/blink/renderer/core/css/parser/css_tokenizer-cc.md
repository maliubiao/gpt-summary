Response:
Let's break down the thought process for analyzing the `css_tokenizer.cc` file.

1. **Understand the Core Purpose:** The filename `css_tokenizer.cc` immediately suggests its primary function: tokenizing CSS. The comments at the top reinforce this by mentioning the CSS Syntax specification. Therefore, the initial focus should be on how it breaks down a CSS string into meaningful units.

2. **Identify Key Classes and Methods:**  Look for the main class definition. Here, it's `CSSTokenizer`. Then, examine its public methods. Methods like `TokenizeSingle`, `TokenizeSingleWithComments`, `NextToken`, `ConsumeNumber`, `ConsumeIdentLikeToken`, `ConsumeStringTokenUntil`, and `ConsumeUrlToken` are strong candidates for core functionality.

3. **Trace the Tokenization Process (Conceptual):**  Imagine the input as a stream of characters. How does the tokenizer process it?  The `NextToken` method appears to be the central function driving this. It reads characters (`Consume()`) and uses a `switch` statement to decide what kind of token it is. This suggests a state machine-like approach, although the comments mention it's a stateless look-ahead tokenizer.

4. **Connect to Web Technologies:**  CSS is directly related to HTML and JavaScript. Consider how the tokenizer interacts with these.
    * **HTML:** The tokenizer helps the browser understand the styling applied to HTML elements. The parsing of CSS rules is a crucial step in rendering web pages.
    * **JavaScript:** JavaScript can manipulate CSS styles dynamically. The tokenizer is involved when JavaScript sets or gets CSS properties, or when the browser re-parses styles due to JavaScript changes.

5. **Analyze Specific Methods (Detailed):**
    * **`NextToken()`:** This is the core. Pay attention to the `switch` cases. Each case handles a different starting character or sequence, leading to the creation of specific token types (e.g., `kWhitespaceToken`, `kStringToken`, `kNumberToken`). The `<SkipComments>` template parameter is interesting – it controls whether comments are treated as tokens or skipped.
    * **`ConsumeNumber()`:**  This method specifically deals with parsing numeric values, including integers and floating-point numbers. Notice how it handles signs, decimal points, and exponents.
    * **`ConsumeIdentLikeToken()`:** This handles identifiers (like CSS property names or keywords) and functions (like `url()`). The handling of the `url()` function is a special case.
    * **`ConsumeStringTokenUntil()`:** This parses string literals enclosed in single or double quotes, handling escape sequences.
    * **`ConsumeUrlToken()`:**  This specifically parses the content of `url()` functions, dealing with potential escape characters and invalid URL characters.

6. **Look for Potential Issues and Edge Cases:**  Consider scenarios where things might go wrong.
    * **Invalid CSS:**  What happens if the CSS is malformed? The tokenizer should try to handle errors gracefully, potentially producing "bad" tokens. `kBadStringToken` and `kBadUrlToken` are indicators of this.
    * **Comments:** The handling of comments (skipping or including them) is a potential point of interest.
    * **Unicode:** The `ConsumeUnicodeRange()` method suggests support for Unicode character ranges.

7. **Infer Logic and Provide Examples:** Based on the method names and their behavior, create hypothetical input and output examples. For instance, feeding `12.3px` to `ConsumeNumericToken` followed by `ConsumeIdentLikeToken` should produce a dimension token.

8. **Consider User Errors and Debugging:** Think about how a developer might encounter this code. Incorrect CSS syntax in stylesheets or inline styles will lead to the tokenizer being called. Understanding the tokenization process is crucial for debugging CSS-related issues. The `prev_offset_` member suggests it tracks the location of tokens, which is helpful for error reporting.

9. **Relate to User Actions:** Connect the code to concrete user interactions. A user browsing a webpage triggers the browser to parse the HTML, which includes parsing the CSS. Any CSS-related issues a user might observe (e.g., incorrect styling) could stem from problems in the tokenization stage.

10. **Structure the Explanation:** Organize the findings logically. Start with a general overview, then delve into specifics, providing examples and relating the code to real-world scenarios. Use clear headings and bullet points to improve readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This seems like a simple character-by-character parsing."
* **Correction:** "The comments about look-ahead and the structure of `NextToken` indicate it's more sophisticated than a simple character-by-character approach. It peeks ahead to make decisions."
* **Initial thought:** "The `block_stack_` is for tracking nested blocks."
* **Refinement:** "Yes, it seems to ensure that opening and closing brackets/parentheses/braces are correctly matched."
* **Initial thought:** "The SIMD code is just an optimization."
* **Refinement:** "While it's an optimization, understanding *why* it's there (speeding up the processing of common cases like identifiers) adds depth to the explanation."

By following these steps, iteratively analyzing the code, and connecting it to the broader context of web development, we can generate a comprehensive explanation of the `css_tokenizer.cc` file.
好的，让我们详细分析一下 `blink/renderer/core/css/parser/css_tokenizer.cc` 这个文件。

**功能概述**

`css_tokenizer.cc` 文件实现了 Chromium Blink 引擎中 CSS 词法分析器（Tokenizer）的功能。它的主要任务是将 CSS 字符串分解成一个个有意义的、可以被后续 CSS 语法分析器（Parser）处理的“令牌”（Token）。

简单来说，它就像一个“切词器”，将一长串 CSS 代码，例如：

```css
.container {
  color: blue;
  font-size: 16px;
}
```

分解成类似这样的令牌序列：

* `.` (DelimiterToken)
* `container` (IdentToken)
* `{` (LeftBraceToken)
* `color` (IdentToken)
* `:` (ColonToken)
* `blue` (IdentToken)
* `;` (SemicolonToken)
* `font-size` (IdentToken)
* `:` (ColonToken)
* `16` (NumberToken)
* `px` (DimensionToken 单位)
* `;` (SemicolonToken)
* `}` (RightBraceToken)

**与 JavaScript, HTML, CSS 的关系**

`css_tokenizer.cc` 是浏览器处理 CSS 的核心组件之一，因此与 HTML 和 JavaScript 都有着密切的关系：

1. **HTML:**
   - **功能关系：** 当浏览器解析 HTML 文件时，遇到 `<style>` 标签或 HTML 元素的 `style` 属性时，会提取其中的 CSS 代码。`css_tokenizer.cc` 负责将这些 CSS 代码转换成令牌流。
   - **举例说明：** 考虑以下 HTML 代码：
     ```html
     <div style="color: red; font-weight: bold;">Hello</div>
     ```
     当浏览器解析到 `style="color: red; font-weight: bold;"` 时，`css_tokenizer.cc` 会将 `"color: red; font-weight: bold;"` 这个字符串作为输入，输出一系列令牌，如 `IdentToken("color")`, `ColonToken`, `IdentToken("red")`, `SemicolonToken`, 等等。

2. **CSS:**
   - **功能关系：** `css_tokenizer.cc` 的主要目的就是为了解析 CSS。它是 CSS 解析流程的第一步，为后续的 CSS 语法分析器提供结构化的输入。
   - **举例说明：**  对于 CSS 文件中的规则：
     ```css
     body {
       background-color: #f0f0f0;
     }
     ```
     `css_tokenizer.cc` 会将其分解为 `IdentToken("body")`, `LeftBraceToken`, `IdentToken("background-color")`, `ColonToken`, `HashToken("#f0f0f0")`, `SemicolonToken`, `RightBraceToken` 等令牌。

3. **JavaScript:**
   - **功能关系：** JavaScript 可以通过 DOM API 操作元素的样式。当 JavaScript 代码修改元素的 `style` 属性，或者使用 `CSSStyleSheet` 接口创建或修改样式规则时，浏览器可能需要重新解析 CSS。`css_tokenizer.cc` 在这些场景下会被调用。
   - **举例说明：**  考虑以下 JavaScript 代码：
     ```javascript
     const element = document.getElementById('myDiv');
     element.style.backgroundColor = 'green';
     ```
     当执行 `element.style.backgroundColor = 'green';` 时，浏览器内部可能会将 `'background-color: green;'` 这样的字符串送入 `css_tokenizer.cc` 进行令牌化。
   - **举例说明（`getComputedStyle`）：** 当 JavaScript 调用 `getComputedStyle(element)` 获取元素的最终样式时，浏览器需要解析应用的 CSS 规则。`css_tokenizer.cc` 在解析这些规则的过程中发挥作用。

**逻辑推理及假设输入与输出**

假设输入以下 CSS 片段：

```css
  width : 100px; /* 宽度 */
```

`css_tokenizer.cc` 的 `TokenizeSingleWithComments()` 方法（假设允许包含注释）可能会输出以下令牌序列（简化表示）：

* `WhitespaceToken("  ")`
* `IdentToken("width")`
* `WhitespaceToken(" ")`
* `ColonToken`
* `WhitespaceToken(" ")`
* `NumberToken(100)`
* `DimensionToken("px")`
* `SemicolonToken`
* `WhitespaceToken(" ")`
* `CommentToken("/* 宽度 */")`

**用户或编程常见的使用错误**

`css_tokenizer.cc` 本身是底层实现，用户或开发者通常不会直接与之交互。然而，用户在编写 CSS 代码时的一些常见错误，会导致 `css_tokenizer.cc` 产生非预期的令牌，进而导致 CSS 解析失败或样式错误。

1. **拼写错误：** 例如，将 `color` 拼写成 `colour`。
   - **假设输入：** `colour: blue;`
   - **`css_tokenizer.cc` 输出：** `IdentToken("colour")`, `ColonToken`, `IdentToken("blue")`, `SemicolonToken`
   - **后续解析：**  由于 `colour` 不是标准的 CSS 属性，后续的 CSS 语法分析器会将其视为无效属性。

2. **缺少冒号或分号：**
   - **假设输入：** `color red`
   - **`css_tokenizer.cc` 输出：** `IdentToken("color")`, `IdentToken("red")`
   - **后续解析：** 语法分析器会因为缺少冒号而报错。

3. **错误的单位：** 例如，将像素单位 `px` 拼写成 `xp`。
   - **假设输入：** `width: 100xp;`
   - **`css_tokenizer.cc` 输出：** `IdentToken("width")`, `ColonToken`, `NumberToken(100)`, `IdentToken("xp")`, `SemicolonToken`
   - **后续解析：** 语法分析器可能会将 `xp` 视为未知的标识符，导致样式应用失败。

4. **URL 格式错误：**
   - **假设输入：** `background-image: url(image.png);` （缺少引号）
   - **`css_tokenizer.cc` 输出：** 可能输出 `UrlToken("image.png")`，但也可能在更严格的解析模式下报错或产生 `BadUrlToken`。  更复杂的错误 URL 可能导致更复杂的令牌序列。

**用户操作如何一步步到达这里作为调试线索**

当用户在浏览器中访问一个网页时，以下步骤可能会触发 `css_tokenizer.cc` 的执行，从而为调试提供线索：

1. **用户请求网页：** 用户在浏览器地址栏输入网址或点击链接。
2. **浏览器下载 HTML：** 浏览器发起请求，服务器返回 HTML 文档。
3. **HTML 解析开始：** 浏览器开始解析 HTML 文档，构建 DOM 树。
4. **遇到 `<style>` 标签或 `style` 属性：** 当 HTML 解析器遇到 `<style>` 标签或元素的 `style` 属性时，会提取其中的 CSS 代码。
5. **调用 CSS 解析器：** 浏览器将提取的 CSS 代码传递给 CSS 解析器。
6. **`css_tokenizer.cc` 执行：** CSS 解析器的第一步通常是词法分析，`css_tokenizer.cc` 负责将 CSS 字符串分解成令牌。
7. **后续 CSS 语法分析和样式应用：**  令牌流被传递给后续的 CSS 语法分析器，构建 CSSOM (CSS Object Model)，最终用于样式计算和页面渲染。

**作为调试线索：**

- **样式未生效或错误：** 如果用户看到网页样式显示不正确，开发者可以使用浏览器的开发者工具（通常是 "Elements" 或 "检查" 面板）查看应用的样式。如果发现某些 CSS 规则没有生效，可能是因为 CSS 代码存在语法错误，导致 `css_tokenizer.cc` 生成了错误的令牌，或者后续的解析器无法正确理解。
- **控制台错误信息：**  浏览器控制台可能会显示 CSS 解析错误信息。这些错误信息通常会指出错误发生的行号和列号，帮助开发者定位问题 CSS 代码。虽然错误信息通常不是直接来自 `css_tokenizer.cc`，但错误的令牌化是导致解析错误的根本原因。
- **断点调试 (高级)：** 对于 Chromium 的开发者，可以在 `css_tokenizer.cc` 中设置断点，观察 CSS 代码是如何被分解成令牌的，以便深入理解解析过程，排查复杂的 CSS 解析问题。

总而言之，`css_tokenizer.cc` 是浏览器理解和应用 CSS 样式的基石。虽然开发者通常不直接操作它，但理解其工作原理对于调试 CSS 相关问题至关重要。用户在编写 CSS 代码时的任何微小错误都可能影响其输出，最终导致页面渲染异常。

Prompt: 
```
这是目录为blink/renderer/core/css/parser/css_tokenizer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"

#include "third_party/blink/renderer/core/css/parser/css_parser_idioms.h"
#include "third_party/blink/renderer/core/css/parser/css_property_parser.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html/parser/input_stream_preprocessor.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"

#ifdef __SSE2__
#include <immintrin.h>
#elif defined(__ARM_NEON__)
#include <arm_neon.h>
#endif

namespace blink {

CSSTokenizer::CSSTokenizer(StringView string, wtf_size_t offset)
    : input_(string) {
  // According to the spec, we should perform preprocessing here.
  // See: https://drafts.csswg.org/css-syntax/#input-preprocessing
  //
  // However, we can skip this step since:
  // * We're using HTML spaces (which accept \r and \f as a valid white space)
  // * Do not count white spaces
  // * CSSTokenizerInputStream::NextInputChar() replaces NULLs for replacement
  //   characters
  input_.Advance(offset);
}

StringView CSSTokenizer::StringRangeFrom(wtf_size_t start) const {
  return input_.RangeFrom(start);
}

StringView CSSTokenizer::StringRangeAt(wtf_size_t start,
                                       wtf_size_t length) const {
  return input_.RangeAt(start, length);
}

CSSParserToken CSSTokenizer::TokenizeSingle() {
  return NextToken</*SkipComments=*/true>();
}

CSSParserToken CSSTokenizer::TokenizeSingleWithComments() {
  return NextToken</*SkipComments=*/false>();
}

wtf_size_t CSSTokenizer::TokenCount() const {
  return token_count_;
}

void CSSTokenizer::Reconsume(UChar c) {
  input_.PushBack(c);
}

UChar CSSTokenizer::Consume() {
  UChar current = input_.NextInputChar();
  input_.Advance();
  return current;
}

CSSParserToken CSSTokenizer::BlockStart(CSSParserTokenType type) {
  block_stack_.push_back(type);
  return CSSParserToken(type, CSSParserToken::kBlockStart);
}

CSSParserToken CSSTokenizer::BlockStart(CSSParserTokenType block_type,
                                        CSSParserTokenType type,
                                        StringView name,
                                        CSSValueID id) {
  block_stack_.push_back(block_type);
  return CSSParserToken(type, name, CSSParserToken::kBlockStart,
                        static_cast<int>(id));
}

CSSParserToken CSSTokenizer::BlockEnd(CSSParserTokenType type,
                                      CSSParserTokenType start_type) {
  if (!block_stack_.empty() && block_stack_.back() == start_type) {
    block_stack_.pop_back();
    return CSSParserToken(type, CSSParserToken::kBlockEnd);
  }
  return CSSParserToken(type);
}

CSSParserToken CSSTokenizer::HyphenMinus(UChar cc) {
  if (NextCharsAreNumber(cc)) {
    Reconsume(cc);
    return ConsumeNumericToken();
  }
  if (input_.PeekWithoutReplacement(0) == '-' &&
      input_.PeekWithoutReplacement(1) == '>') {
    input_.Advance(2);
    return CSSParserToken(kCDCToken);
  }
  if (NextCharsAreIdentifier(cc)) {
    Reconsume(cc);
    return ConsumeIdentLikeToken();
  }
  return CSSParserToken(kDelimiterToken, cc);
}

CSSParserToken CSSTokenizer::Hash(UChar cc) {
  UChar next_char = input_.PeekWithoutReplacement(0);
  if (IsNameCodePoint(next_char) ||
      TwoCharsAreValidEscape(next_char, input_.PeekWithoutReplacement(1))) {
    HashTokenType type =
        NextCharsAreIdentifier() ? kHashTokenId : kHashTokenUnrestricted;
    return CSSParserToken(type, ConsumeName());
  }

  return CSSParserToken(kDelimiterToken, cc);
}

CSSParserToken CSSTokenizer::LetterU(UChar cc) {
  if (unicode_ranges_allowed_ && input_.PeekWithoutReplacement(0) == '+' &&
      (IsASCIIHexDigit(input_.PeekWithoutReplacement(1)) ||
       input_.PeekWithoutReplacement(1) == '?')) {
    input_.Advance();
    return ConsumeUnicodeRange();
  }
  Reconsume(cc);
  return ConsumeIdentLikeToken();
}

template <bool SkipComments>
CSSParserToken CSSTokenizer::NextToken() {
  do {
    prev_offset_ = input_.Offset();
    // Unlike the HTMLTokenizer, the CSS Syntax spec is written
    // as a stateless, (fixed-size) look-ahead tokenizer.
    // We could move to the stateful model and instead create
    // states for all the "next 3 codepoints are X" cases.
    // State-machine tokenizers are easier to write to handle
    // incremental tokenization of partial sources.
    // However, for now we follow the spec exactly.
    UChar cc = Consume();
    ++token_count_;

    switch (cc) {
      case 0:
        return CSSParserToken(kEOFToken);
      case '\t':
      case '\n':
      case '\f':
      case '\r':
      case ' ':
        input_.AdvanceUntilNonWhitespace();
        return CSSParserToken(kWhitespaceToken);
      case '\'':
      case '"':
        return ConsumeStringTokenUntil(cc);
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
        Reconsume(cc);
        return ConsumeNumericToken();
      case '(':
        return BlockStart(kLeftParenthesisToken);
      case ')':
        return BlockEnd(kRightParenthesisToken, kLeftParenthesisToken);
      case '[':
        return BlockStart(kLeftBracketToken);
      case ']':
        return BlockEnd(kRightBracketToken, kLeftBracketToken);
      case '{':
        return BlockStart(kLeftBraceToken);
      case '}':
        return BlockEnd(kRightBraceToken, kLeftBraceToken);
      case '+':
      case '.':
        if (NextCharsAreNumber(cc)) {
          Reconsume(cc);
          return ConsumeNumericToken();
        }
        return CSSParserToken(kDelimiterToken, cc);
      case '-':
        return HyphenMinus(cc);
      case '*':
        if (ConsumeIfNext('=')) {
          return CSSParserToken(kSubstringMatchToken);
        }
        return CSSParserToken(kDelimiterToken, '*');
      case '<':
        if (input_.PeekWithoutReplacement(0) == '!' &&
            input_.PeekWithoutReplacement(1) == '-' &&
            input_.PeekWithoutReplacement(2) == '-') {
          input_.Advance(3);
          return CSSParserToken(kCDOToken);
        }
        return CSSParserToken(kDelimiterToken, '<');
      case ',':
        return CSSParserToken(kCommaToken);
      case '/':
        if (ConsumeIfNext('*')) {
          ConsumeUntilCommentEndFound();
          if (SkipComments) {
            break;  // Read another token.
          } else {
            return CSSParserToken(kCommentToken);
          }
        }
        return CSSParserToken(kDelimiterToken, cc);
      case '\\':
        if (TwoCharsAreValidEscape(cc, input_.PeekWithoutReplacement(0))) {
          Reconsume(cc);
          return ConsumeIdentLikeToken();
        }
        return CSSParserToken(kDelimiterToken, cc);
      case ':':
        return CSSParserToken(kColonToken);
      case ';':
        return CSSParserToken(kSemicolonToken);
      case '#':
        return Hash(cc);
      case '^':
        if (ConsumeIfNext('=')) {
          return CSSParserToken(kPrefixMatchToken);
        }
        return CSSParserToken(kDelimiterToken, '^');
      case '$':
        if (ConsumeIfNext('=')) {
          return CSSParserToken(kSuffixMatchToken);
        }
        return CSSParserToken(kDelimiterToken, '$');
      case '|':
        if (ConsumeIfNext('=')) {
          return CSSParserToken(kDashMatchToken);
        }
        if (ConsumeIfNext('|')) {
          return CSSParserToken(kColumnToken);
        }
        return CSSParserToken(kDelimiterToken, '|');
      case '~':
        if (ConsumeIfNext('=')) {
          return CSSParserToken(kIncludeMatchToken);
        }
        return CSSParserToken(kDelimiterToken, '~');
      case '@':
        if (NextCharsAreIdentifier()) {
          return CSSParserToken(kAtKeywordToken, ConsumeName());
        }
        return CSSParserToken(kDelimiterToken, '@');
      case 'u':
      case 'U':
        return LetterU(cc);
      case 1:
      case 2:
      case 3:
      case 4:
      case 5:
      case 6:
      case 7:
      case 8:
      case 11:
      case 14:
      case 15:
      case 16:
      case 17:
      case 18:
      case 19:
      case 20:
      case 21:
      case 22:
      case 23:
      case 24:
      case 25:
      case 26:
      case 27:
      case 28:
      case 29:
      case 30:
      case 31:
      case '!':
      case '%':
      case '&':
      case '=':
      case '>':
      case '?':
      case '`':
      case 127:
        return CSSParserToken(kDelimiterToken, cc);
      default:
        Reconsume(cc);
        return ConsumeIdentLikeToken();
    }
  } while (SkipComments);
}

// This method merges the following spec sections for efficiency
// http://www.w3.org/TR/css3-syntax/#consume-a-number
// http://www.w3.org/TR/css3-syntax/#convert-a-string-to-a-number
CSSParserToken CSSTokenizer::ConsumeNumber() {
  DCHECK(NextCharsAreNumber());

  NumericValueType type = kIntegerValueType;
  NumericSign sign = kNoSign;
  unsigned number_length = 0;
  unsigned sign_length = 0;

  UChar next = input_.PeekWithoutReplacement(0);
  if (next == '+') {
    ++number_length;
    ++sign_length;
    sign = kPlusSign;
  } else if (next == '-') {
    ++number_length;
    ++sign_length;
    sign = kMinusSign;
  }

  number_length = input_.SkipWhilePredicate<IsASCIIDigit>(number_length);
  next = input_.PeekWithoutReplacement(number_length);
  if (next == '.' &&
      IsASCIIDigit(input_.PeekWithoutReplacement(number_length + 1))) {
    type = kNumberValueType;
    number_length = input_.SkipWhilePredicate<IsASCIIDigit>(number_length + 2);
    next = input_.PeekWithoutReplacement(number_length);
  }

  if (next == 'E' || next == 'e') {
    next = input_.PeekWithoutReplacement(number_length + 1);
    if (IsASCIIDigit(next)) {
      type = kNumberValueType;
      number_length =
          input_.SkipWhilePredicate<IsASCIIDigit>(number_length + 1);
    } else if ((next == '+' || next == '-') &&
               IsASCIIDigit(input_.PeekWithoutReplacement(number_length + 2))) {
      type = kNumberValueType;
      number_length =
          input_.SkipWhilePredicate<IsASCIIDigit>(number_length + 3);
    }
  }

  double value;
  if (type == kIntegerValueType) {
    // Fast path.
    value = input_.GetNaturalNumberAsDouble(sign_length, number_length);
    if (sign == kMinusSign) {
      value = -value;
    }
    DCHECK_EQ(value, input_.GetDouble(0, number_length));
    input_.Advance(number_length);
  } else {
    value = input_.GetDouble(0, number_length);
    input_.Advance(number_length);
  }

  return CSSParserToken(kNumberToken, value, type, sign);
}

// http://www.w3.org/TR/css3-syntax/#consume-a-numeric-token
CSSParserToken CSSTokenizer::ConsumeNumericToken() {
  CSSParserToken token = ConsumeNumber();
  if (NextCharsAreIdentifier()) {
    token.ConvertToDimensionWithUnit(ConsumeName());
  } else if (ConsumeIfNext('%')) {
    token.ConvertToPercentage();
  }
  return token;
}

// https://drafts.csswg.org/css-syntax/#consume-ident-like-token
CSSParserToken CSSTokenizer::ConsumeIdentLikeToken() {
  StringView name = ConsumeName();
  if (ConsumeIfNext('(')) {
    if (EqualIgnoringASCIICase(name, "url")) {
      // The spec is slightly different so as to avoid dropping whitespace
      // tokens, but they wouldn't be used and this is easier.
      input_.AdvanceUntilNonWhitespace();
      UChar next = input_.PeekWithoutReplacement(0);
      if (next != '"' && next != '\'') {
        return ConsumeUrlToken();
      }
    }
    return BlockStart(kLeftParenthesisToken, kFunctionToken, name,
                      CssValueKeywordID(name));
  }
  return CSSParserToken(kIdentToken, name);
}

// https://drafts.csswg.org/css-syntax/#consume-a-string-token
CSSParserToken CSSTokenizer::ConsumeStringTokenUntil(UChar ending_code_point) {
  // Strings without escapes get handled without allocations
  for (unsigned size = 0;; size++) {
    UChar cc = input_.PeekWithoutReplacement(size);
    if (cc == ending_code_point) {
      unsigned start_offset = input_.Offset();
      input_.Advance(size + 1);
      return CSSParserToken(kStringToken, input_.RangeAt(start_offset, size));
    }
    if (IsCSSNewLine(cc)) {
      input_.Advance(size);
      return CSSParserToken(kBadStringToken);
    }
    if (cc == '\0' || cc == '\\') {
      break;
    }
  }

  StringBuilder output;
  while (true) {
    UChar cc = Consume();
    if (cc == ending_code_point || cc == kEndOfFileMarker) {
      return CSSParserToken(kStringToken,
                            RegisterString(output.ReleaseString()));
    }
    if (IsCSSNewLine(cc)) {
      Reconsume(cc);
      return CSSParserToken(kBadStringToken);
    }
    if (cc == '\\') {
      if (input_.NextInputChar() == kEndOfFileMarker) {
        continue;
      }
      if (IsCSSNewLine(input_.PeekWithoutReplacement(0))) {
        ConsumeSingleWhitespaceIfNext();  // This handles \r\n for us
      } else {
        output.Append(ConsumeEscape());
      }
    } else {
      output.Append(cc);
    }
  }
}

CSSParserToken CSSTokenizer::ConsumeUnicodeRange() {
  DCHECK(IsASCIIHexDigit(input_.PeekWithoutReplacement(0)) ||
         input_.PeekWithoutReplacement(0) == '?');
  int length_remaining = 6;
  UChar32 start = 0;

  while (length_remaining &&
         IsASCIIHexDigit(input_.PeekWithoutReplacement(0))) {
    start = start * 16 + ToASCIIHexValue(Consume());
    --length_remaining;
  }

  UChar32 end = start;
  if (length_remaining && ConsumeIfNext('?')) {
    do {
      start *= 16;
      end = end * 16 + 0xF;
      --length_remaining;
    } while (length_remaining && ConsumeIfNext('?'));
  } else if (input_.PeekWithoutReplacement(0) == '-' &&
             IsASCIIHexDigit(input_.PeekWithoutReplacement(1))) {
    input_.Advance();
    length_remaining = 6;
    end = 0;
    do {
      end = end * 16 + ToASCIIHexValue(Consume());
      --length_remaining;
    } while (length_remaining &&
             IsASCIIHexDigit(input_.PeekWithoutReplacement(0)));
  }

  return CSSParserToken(kUnicodeRangeToken, start, end);
}

// https://drafts.csswg.org/css-syntax/#non-printable-code-point
static bool IsNonPrintableCodePoint(UChar cc) {
  return (cc >= '\0' && cc <= '\x8') || cc == '\xb' ||
         (cc >= '\xe' && cc <= '\x1f') || cc == '\x7f';
}

// https://drafts.csswg.org/css-syntax/#consume-url-token
CSSParserToken CSSTokenizer::ConsumeUrlToken() {
  input_.AdvanceUntilNonWhitespace();

  // URL tokens without escapes get handled without allocations
  for (unsigned size = 0;; size++) {
    UChar cc = input_.PeekWithoutReplacement(size);
    if (cc == ')') {
      unsigned start_offset = input_.Offset();
      input_.Advance(size + 1);
      return CSSParserToken(kUrlToken, input_.RangeAt(start_offset, size));
    }
    if (cc <= ' ' || cc == '\\' || cc == '"' || cc == '\'' || cc == '(' ||
        cc == '\x7f') {
      break;
    }
  }

  StringBuilder result;
  while (true) {
    UChar cc = Consume();
    if (cc == ')' || cc == kEndOfFileMarker) {
      return CSSParserToken(kUrlToken, RegisterString(result.ReleaseString()));
    }

    if (IsHTMLSpace(cc)) {
      input_.AdvanceUntilNonWhitespace();
      if (ConsumeIfNext(')') || input_.NextInputChar() == kEndOfFileMarker) {
        return CSSParserToken(kUrlToken,
                              RegisterString(result.ReleaseString()));
      }
      break;
    }

    if (cc == '"' || cc == '\'' || cc == '(' || IsNonPrintableCodePoint(cc)) {
      break;
    }

    if (cc == '\\') {
      if (TwoCharsAreValidEscape(cc, input_.PeekWithoutReplacement(0))) {
        result.Append(ConsumeEscape());
        continue;
      }
      break;
    }

    result.Append(cc);
  }

  ConsumeBadUrlRemnants();
  return CSSParserToken(kBadUrlToken);
}

// https://drafts.csswg.org/css-syntax/#consume-the-remnants-of-a-bad-url
void CSSTokenizer::ConsumeBadUrlRemnants() {
  while (true) {
    UChar cc = Consume();
    if (cc == ')' || cc == kEndOfFileMarker) {
      return;
    }
    if (TwoCharsAreValidEscape(cc, input_.PeekWithoutReplacement(0))) {
      ConsumeEscape();
    }
  }
}

void CSSTokenizer::ConsumeSingleWhitespaceIfNext() {
  blink::ConsumeSingleWhitespaceIfNext(input_);
}

void CSSTokenizer::ConsumeUntilCommentEndFound() {
  UChar c = Consume();
  while (true) {
    if (c == kEndOfFileMarker) {
      return;
    }
    if (c != '*') {
      c = Consume();
      continue;
    }
    c = Consume();
    if (c == '/') {
      return;
    }
  }
}

bool CSSTokenizer::ConsumeIfNext(UChar character) {
  // Since we're not doing replacement we can't tell the difference from
  // a NUL in the middle and the kEndOfFileMarker, so character must not be
  // NUL.
  DCHECK(character);
  if (input_.PeekWithoutReplacement(0) == character) {
    input_.Advance();
    return true;
  }
  return false;
}

// http://www.w3.org/TR/css3-syntax/#consume-name
//
// Consumes a name, which is defined as a contiguous sequence of name code
// points (see IsNameCodePoint()), possibly with escapes. We stop at the first
// thing that is _not_ a name code point (or the end of a string); if that is a
// backslash, we hand over to the more complete and slower blink::ConsumeName().
// If not, we can send back the relevant substring of the input, without any
// allocations.
//
// If SIMD is available (we support only SSE2 and NEON), we do this 16 and 16
// bytes at a time, generally giving a speed boost except for very short names.
// (We don't get short-circuiting, and we need some extra setup to load
// constants, but we also don't get a lot of branches per byte that we
// consider.)
//
// The checking for \0 is a bit odd; \0 is sometimes used as an EOF marker
// internal to this code, so we need to call into blink::ConsumeName()
// to escape it (into a Unicode replacement character) if we should see it.
StringView CSSTokenizer::ConsumeName() {
  StringView buffer = input_.Peek();

  unsigned size = 0;
#if defined(__SSE2__) || defined(__ARM_NEON__)
  if (buffer.Is8Bit()) {
    const LChar* ptr = buffer.Characters8();
    while (size + 16 <= buffer.length()) {
      int8_t b __attribute__((vector_size(16)));
      memcpy(&b, ptr + size, sizeof(b));

      // Exactly the same as IsNameCodePoint(), except the IsASCII() part,
      // which we deal with below. Note that we compute the inverted condition,
      // since __builtin_ctz wants to find the first 1-bit, not the first 0-bit.
      auto non_name_mask = ((b | 0x20) < 'a' || (b | 0x20) > 'z') && b != '_' &&
                           b != '-' && (b < '0' || b > '9');
#ifdef __SSE2__
      // pmovmskb extracts only the top bit and ignores the rest,
      // so to implement the IsASCII() test, which for LChar only
      // tests whether the top bit is set, we don't need a compare;
      // we can just rely on the top bit directly (using a PANDN).
      uint16_t bits =
          _mm_movemask_epi8(reinterpret_cast<__m128i>(non_name_mask & ~b));
      if (bits == 0) {
        size += 16;
        continue;
      }

      // We found either the end, or a sign that we need escape-aware parsing.
      size += __builtin_ctz(bits);
#else  // __ARM_NEON__

      // NEON doesn't have pmovmskb, so we'll need to do the actual compare
      // (or something similar, like shifting). Now the mask is either all-zero
      // or all-one for each byte, so we can use the code from
      // https://community.arm.com/arm-community-blogs/b/infrastructure-solutions-blog/posts/porting-x86-vector-bitmask-optimizations-to-arm-neon
      non_name_mask = non_name_mask && (b >= 0);
      uint8x8_t narrowed_mask =
          vshrn_n_u16(vreinterpretq_u16_s8(non_name_mask), 4);
      uint64_t bits = vget_lane_u64(vreinterpret_u64_u8(narrowed_mask), 0);
      if (bits == 0) {
        size += 16;
        continue;
      }

      // We found either the end, or a sign that we need escape-aware parsing.
      size += __builtin_ctzll(bits) >> 2;
#endif
      if (ptr[size] == '\0' || ptr[size] == '\\') {
        // We need escape-aware parsing.
        return RegisterString(blink::ConsumeName(input_));
      } else {
        input_.Advance(size);
        return StringView(buffer, 0, size);
      }
    }
    // Fall back to the slow path for the last <= 15 bytes of the string.
  }
#endif  // SIMD

  // Slow path for non-UTF-8 and tokens near the end of the string.
  for (; size < buffer.length(); ++size) {
    UChar cc = buffer[size];
    if (!IsNameCodePoint(cc)) {
      // End of this token, but not end of the string.
      if (cc == '\0' || cc == '\\') {
        // We need escape-aware parsing.
        return RegisterString(blink::ConsumeName(input_));
      } else {
        // Names without escapes get handled without allocations
        input_.Advance(size);
        return StringView(buffer, 0, size);
      }
    }
  }

  // The entire rest of the string is a name.
  input_.Advance(size);
  return buffer;
}

// https://drafts.csswg.org/css-syntax/#consume-an-escaped-code-point
UChar32 CSSTokenizer::ConsumeEscape() {
  return blink::ConsumeEscape(input_);
}

bool CSSTokenizer::NextTwoCharsAreValidEscape() {
  return TwoCharsAreValidEscape(input_.PeekWithoutReplacement(0),
                                input_.PeekWithoutReplacement(1));
}

// http://www.w3.org/TR/css3-syntax/#starts-with-a-number
bool CSSTokenizer::NextCharsAreNumber(UChar first) {
  UChar second = input_.PeekWithoutReplacement(0);
  if (IsASCIIDigit(first)) {
    return true;
  }
  if (first == '+' || first == '-') {
    return ((IsASCIIDigit(second)) ||
            (second == '.' && IsASCIIDigit(input_.PeekWithoutReplacement(1))));
  }
  if (first == '.') {
    return (IsASCIIDigit(second));
  }
  return false;
}

bool CSSTokenizer::NextCharsAreNumber() {
  UChar first = Consume();
  bool are_number = NextCharsAreNumber(first);
  Reconsume(first);
  return are_number;
}

// https://drafts.csswg.org/css-syntax/#would-start-an-identifier
bool CSSTokenizer::NextCharsAreIdentifier(UChar first) {
  return blink::NextCharsAreIdentifier(first, input_);
}

bool CSSTokenizer::NextCharsAreIdentifier() {
  UChar first = Consume();
  bool are_identifier = NextCharsAreIdentifier(first);
  Reconsume(first);
  return are_identifier;
}

StringView CSSTokenizer::RegisterString(const String& string) {
  string_pool_.push_back(string);
  return string;
}

}  // namespace blink

"""

```