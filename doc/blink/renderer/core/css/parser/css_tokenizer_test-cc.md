Response:
Let's break down the thought process for analyzing the `css_tokenizer_test.cc` file.

1. **Understand the Purpose:** The file name `css_tokenizer_test.cc` immediately suggests its primary function: testing the CSS tokenizer. The `_test.cc` suffix is a common convention in C++ projects (especially those using Google Test) for identifying test files.

2. **Identify Key Components:**  Scan the file for important elements:
    * **Includes:** `#include` directives tell us what other code this file relies on. We see includes for `css_tokenizer.h`, `gtest/gtest.h`, and `css_parser_token_stream.h`. This reinforces the idea that it's testing the tokenizer. The `wtf/allocator/partitions.h` include is a bit more specific to Blink's internal workings.
    * **Namespace:** `namespace blink { ... }` indicates this code belongs to the Blink rendering engine.
    * **Macros:**  The `#define TEST_TOKENS` macro is a strong indicator of the testing methodology.
    * **Helper Functions:** Look for functions that simplify the test setup, such as `CompareTokens`, `TestTokens`, `Ident`, `GetString`, etc.
    * **Test Cases:** The `TEST(CSSTokenizerTest, ...)` blocks are the actual test functions.
    * **Data Structures (implicitly):** The presence of `CSSParserToken` and `CSSParserTokenStream` implies the tokenizer produces a stream of these tokens.

3. **Analyze the Testing Strategy:**
    * **`TEST_TOKENS` Macro:** This macro is central. It takes a CSS string and a series of expected tokens. It then uses `CSSParserTokenStream` to tokenize the input and compares the resulting tokens with the expected ones. The `SCOPED_TRACE` is helpful for debugging.
    * **Helper Functions for Token Creation:** Functions like `Ident`, `GetString`, `Number`, `Dimension`, etc., simplify the creation of `CSSParserToken` objects for comparison. This makes the tests more readable.
    * **`CompareTokens` Function:** This function is crucial for the actual comparison. It checks the token type and, based on the type, compares relevant attributes (value, delimiter, numeric value, etc.).
    * **`TestTokens` Function:** This function orchestrates the tokenization and comparison. It creates a `CSSParserTokenStream`, enables Unicode range parsing if needed, and then iterates through the expected tokens, comparing them with the tokens produced by the stream.
    * **`TestUnicodeRangeTokens`:** This is a specialized version of `TestTokens` for testing Unicode range tokens.

4. **Connect to Core Web Technologies:**
    * **CSS:** The file's name and content directly relate to CSS. The tokenizer's job is to break down CSS text into meaningful units (tokens).
    * **HTML:** While the tokenizer itself doesn't directly process HTML, CSS is used to style HTML. The tokens produced by this tokenizer will eventually be used when rendering HTML.
    * **JavaScript:**  JavaScript can interact with CSS (e.g., through the CSSOM). The output of this tokenizer is a foundational step in allowing JavaScript to understand and manipulate styles.

5. **Consider Logical Inference and Examples:**
    * **Assumption:** The tokenizer should correctly identify different types of CSS tokens.
    * **Input:** `"color: blue;"`
    * **Expected Output:** `Ident("color")`, `Colon`, `Ident("blue")`, `Semicolon`
    * **Input:** `"10px"`
    * **Expected Output:** `Dimension(kIntegerValueType, 10, "px")`

6. **Think About User/Developer Errors:**
    * **Incorrect CSS Syntax:** If a user writes invalid CSS, the tokenizer needs to handle it gracefully (potentially by producing error tokens or failing in a predictable way). The tests demonstrate how the tokenizer handles things like unterminated strings or bad URLs.
    * **Developer Misuse of the API (Hypothetical):** A developer using the `CSSParserTokenStream` might forget to consume tokens, leading to unexpected results when peeking. The tests implicitly verify the correct behavior of the stream's methods.

7. **Trace User Interaction (Debugging Perspective):**
    * **User writes CSS:**  A user types CSS code in a `<style>` tag, an external CSS file, or inline styles.
    * **Browser parses HTML:** The HTML parser encounters the CSS.
    * **CSS parser is invoked:** The browser's CSS parser is triggered.
    * **Tokenizer is the first step:** The `CSSParserTokenStream` (using the `CSSTokenizer`) is the first stage in the CSS parsing process. It breaks the CSS text into a stream of tokens.
    * **Test file simulates this:**  This test file directly exercises the `CSSTokenizer` and `CSSParserTokenStream` with various CSS snippets to ensure correct tokenization.

8. **Refine and Organize:** Structure the analysis into logical sections (functionality, relationships, examples, errors, debugging) for clarity. Use precise language and refer to specific elements within the code.

By following these steps, one can systematically analyze the `css_tokenizer_test.cc` file and understand its role in the Chromium Blink engine. The process involves code inspection, understanding testing methodologies, connecting the code to broader web technologies, and considering practical implications.
这个文件 `blink/renderer/core/css/parser/css_tokenizer_test.cc` 是 Chromium Blink 引擎中 **CSS 词法分析器 (Tokenizer)** 的 **单元测试** 文件。它的主要功能是：

**核心功能:**

1. **测试 CSS 词法分析器的正确性:**  它通过编写一系列的测试用例，验证 `CSSParserTokenStream` 和底层的 `CSSTokenizer` 能否将不同的 CSS 字符串正确地分解成一个个的 **CSS 令牌 (Token)**。

**与 JavaScript, HTML, CSS 的关系:**

这个测试文件直接关联的是 **CSS** 的功能。 词法分析是 CSS 解析的第一步，它将原始的 CSS 文本转换为结构化的令牌流，以便后续的 CSS 语法分析器进行处理。

* **CSS:**  这个文件测试的就是如何将 CSS 字符串 (例如 `"color: blue;"`, `"10px"`) 转换为一个个有意义的令牌，比如标识符 (identifier, 如 "color", "blue")、冒号 (colon)、长度单位 (dimension, 如 "10px") 等。

* **HTML:** 当浏览器解析 HTML 文档时，如果遇到 `<style>` 标签或者 `<link>` 标签引用的 CSS 文件，就会调用 CSS 解析器。  `CSSTokenizer` 作为 CSS 解析的第一步，负责将 CSS 代码分解成令牌。  例如，如果 HTML 中有 `<style>body { color: red; }</style>`，`CSSTokenizer` 会将 `"body { color: red; }"`  分解成 `Ident("body")`, `LeftBrace()`, `Ident("color")`, `Colon()`, `Ident("red")`, `Semicolon()`, `RightBrace()` 等令牌。

* **JavaScript:**  JavaScript 可以通过 CSSOM (CSS Object Model) 操作页面的样式。 当 JavaScript 代码获取或修改元素的样式时，浏览器内部也会涉及到 CSS 的解析。  `CSSTokenizer` 仍然是这个过程中的关键组成部分，负责将 CSS 字符串 (例如通过 `element.style.width = '100px'`) 转换为令牌，以便应用到元素的样式上。

**举例说明:**

假设我们有以下 CSS 代码片段：

```css
.container {
  width: 100px;
  color: blue;
}
```

`css_tokenizer_test.cc` 中会有类似的测试用例来验证 `CSSTokenizer` 的行为：

**假设输入:**  `".container { width: 100px; color: blue; }"`

**预期输出 (通过测试函数验证):**

* `Delim('.')`  (表示 '.')
* `Ident("container")`
* `Whitespace()`
* `LeftBrace()`
* `Whitespace()`
* `Ident("width")`
* `Colon()`
* `Whitespace()`
* `Dimension(kIntegerValueType, 100, "px")`  (表示 "100px" 这个长度单位)
* `Semicolon()`
* `Whitespace()`
* `Ident("color")`
* `Colon()`
* `Whitespace()`
* `Ident("blue")`
* `Semicolon()`
* `Whitespace()`
* `RightBrace()`

文件中的 `TEST_TOKENS` 宏就是用来方便地定义这样的测试用例，指定输入字符串和预期的令牌序列。

**逻辑推理与假设输入/输出:**

测试用例通常会覆盖 CSS 语法中的各种情况，包括：

* **不同的令牌类型:** 标识符、数字、字符串、标点符号、运算符等。
* **边界情况:** 空字符串、只有空格的字符串、以特殊字符开头的字符串等。
* **转义字符:**  例如 `hel\\6Co` 应该被解析为 `hello`。
* **Unicode 字符:** 测试对各种 Unicode 字符的处理。
* **注释:**  验证注释是否被正确忽略。

例如，对于 Unicode 范围令牌的测试：

**假设输入:** `"u+012345-123456"`

**预期输出:** `UnicodeRng(0x012345, 0x123456)`

**涉及用户或编程常见的使用错误:**

这个测试文件可以间接地帮助发现和避免用户或开发者在编写 CSS 时可能犯的错误，以及解析器在处理这些错误时的行为：

* **未闭合的字符串:** 例如 `"hello`。  测试会验证 `CSSTokenizer` 会产生 `BadString` 类型的令牌。
* **错误的 URL 格式:** 例如 `url(invalid url)`。 测试会验证 `CSSTokenizer` 会产生 `BadUrl` 类型的令牌。
* **错误的数字格式:** 虽然 `CSSTokenizer` 主要负责词法分析，不负责语义验证，但它可以帮助识别出不是有效数字序列的部分。

**用户操作如何一步步到达这里 (调试线索):**

当开发者在 Chromium 浏览器中进行调试，发现 CSS 样式没有正确应用，或者在开发工具中查看元素的样式时发现解析错误，他们可能会怀疑是 CSS 解析器的问题。  以下是一些可能的调试步骤，最终可能会涉及到 `css_tokenizer_test.cc`：

1. **查看开发者工具的 "Elements" 面板:**  检查元素的 "Styles" 选项卡，看是否有样式被覆盖或者有解析错误提示。

2. **使用 "Sources" 面板调试 CSS 文件:**  设置断点，查看 CSS 解析器在处理特定 CSS 代码时的行为。

3. **阅读 Chromium 源代码:**  如果怀疑是词法分析阶段的问题，开发者可能会查看 `blink/renderer/core/css/parser/` 目录下的相关代码，包括 `css_tokenizer.cc` 和 `css_parser_token_stream.cc`。

4. **运行单元测试:**  为了验证 `CSSTokenizer` 的正确性，开发者会运行 `css_tokenizer_test.cc` 中的单元测试。  如果某个测试用例失败，就表明 `CSSTokenizer` 在处理特定的 CSS 语法时存在问题。

5. **修改代码并重新测试:**  根据失败的测试用例，开发者会修改 `css_tokenizer.cc` 中的代码，修复 bug，然后重新运行测试，直到所有测试用例都通过。

因此，`css_tokenizer_test.cc` 虽然不是用户直接操作的对象，但它是保证 CSS 解析器正确性的重要组成部分，当用户遇到 CSS 相关的 bug 时，开发者可能会通过分析和运行这个测试文件来定位和解决问题。

### 提示词
```
这是目录为blink/renderer/core/css/parser/css_tokenizer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token_stream.h"
#include "third_party/blink/renderer/platform/wtf/allocator/partitions.h"

namespace blink {

// This let's us see the line numbers of failing tests
#define TEST_TOKENS(string, ...)     \
  {                                  \
    String s = string;               \
    SCOPED_TRACE(s);                 \
    TestTokens(string, __VA_ARGS__); \
  }

void CompareTokens(const CSSParserToken& expected,
                   const CSSParserToken& actual) {
  ASSERT_EQ(expected.GetType(), actual.GetType());
  switch (expected.GetType()) {
    case kDelimiterToken:
      ASSERT_EQ(expected.Delimiter(), actual.Delimiter());
      break;
    case kIdentToken:
    case kFunctionToken:
    case kStringToken:
    case kUrlToken:
      ASSERT_EQ(expected.Value(), actual.Value());
      break;
    case kDimensionToken:
      ASSERT_EQ(expected.Value(), actual.Value());
      ASSERT_EQ(expected.GetNumericValueType(), actual.GetNumericValueType());
      ASSERT_DOUBLE_EQ(expected.NumericValue(), actual.NumericValue());
      break;
    case kNumberToken:
      ASSERT_EQ(expected.GetNumericSign(), actual.GetNumericSign());
      [[fallthrough]];
    case kPercentageToken:
      ASSERT_EQ(expected.GetNumericValueType(), actual.GetNumericValueType());
      ASSERT_DOUBLE_EQ(expected.NumericValue(), actual.NumericValue());
      break;
    case kUnicodeRangeToken:
      ASSERT_EQ(expected.UnicodeRangeStart(), actual.UnicodeRangeStart());
      ASSERT_EQ(expected.UnicodeRangeEnd(), actual.UnicodeRangeEnd());
      break;
    case kHashToken:
      ASSERT_EQ(expected.Value(), actual.Value());
      ASSERT_EQ(expected.GetHashTokenType(), actual.GetHashTokenType());
      break;
    default:
      break;
  }
}

void TestTokens(const String& string,
                const CSSParserToken& token1,
                const CSSParserToken& token2 = CSSParserToken(kEOFToken),
                const CSSParserToken& token3 = CSSParserToken(kEOFToken),
                bool unicode_ranges_allowed = false) {
  CSSParserTokenStream stream(string);
  CSSParserTokenStream::EnableUnicodeRanges enable(stream,
                                                   unicode_ranges_allowed);
  CompareTokens(token1, stream.Peek());
  if (!stream.AtEnd()) {
    stream.ConsumeRaw();
    CompareTokens(token2, stream.Peek());
    if (!stream.AtEnd()) {
      stream.ConsumeRaw();
      CompareTokens(token3, stream.Peek());
    }
  }
}

void TestUnicodeRangeTokens(
    const String& string,
    const CSSParserToken& token1,
    const CSSParserToken& token2 = CSSParserToken(kEOFToken),
    const CSSParserToken& token3 = CSSParserToken(kEOFToken)) {
  TEST_TOKENS(string, token1, token2, token3, true);
}

static CSSParserToken Ident(const String& string) {
  return CSSParserToken(kIdentToken, string);
}
static CSSParserToken AtKeyword(const String& string) {
  return CSSParserToken(kAtKeywordToken, string);
}
static CSSParserToken GetString(const String& string) {
  return CSSParserToken(kStringToken, string);
}
static CSSParserToken Func(const String& string) {
  return CSSParserToken(kFunctionToken, string);
}
static CSSParserToken Url(const String& string) {
  return CSSParserToken(kUrlToken, string);
}
static CSSParserToken GetHash(const String& string, HashTokenType type) {
  return CSSParserToken(type, string);
}
static CSSParserToken Delim(char c) {
  return CSSParserToken(kDelimiterToken, c);
}

static CSSParserToken UnicodeRng(UChar32 start, UChar32 end) {
  return CSSParserToken(kUnicodeRangeToken, start, end);
}

static CSSParserToken Number(NumericValueType type,
                             double value,
                             NumericSign sign) {
  return CSSParserToken(kNumberToken, value, type, sign);
}

static CSSParserToken Dimension(NumericValueType type,
                                double value,
                                const String& string) {
  CSSParserToken token = Number(type, value, kNoSign);  // sign ignored
  token.ConvertToDimensionWithUnit(string);
  return token;
}

static CSSParserToken Percentage(NumericValueType type, double value) {
  CSSParserToken token = Number(type, value, kNoSign);  // sign ignored
  token.ConvertToPercentage();
  return token;
}

// We need to initialize PartitionAlloc before creating CSSParserTokens
// because CSSParserToken depends on PartitionAlloc. It is safe to call
// WTF::Partitions::initialize() multiple times.
#define DEFINE_TOKEN(name, argument)                       \
  static CSSParserToken& name() {                          \
    WTF::Partitions::Initialize();                         \
    DEFINE_STATIC_LOCAL(CSSParserToken, name, (argument)); \
    return name;                                           \
  }

DEFINE_TOKEN(Whitespace, (kWhitespaceToken))
DEFINE_TOKEN(Colon, (kColonToken))
DEFINE_TOKEN(Semicolon, (kSemicolonToken))
DEFINE_TOKEN(Comma, (kCommaToken))
DEFINE_TOKEN(IncludeMatch, (kIncludeMatchToken))
DEFINE_TOKEN(DashMatch, (kDashMatchToken))
DEFINE_TOKEN(PrefixMatch, (kPrefixMatchToken))
DEFINE_TOKEN(SuffixMatch, (kSuffixMatchToken))
DEFINE_TOKEN(SubstringMatch, (kSubstringMatchToken))
DEFINE_TOKEN(Column, (kColumnToken))
DEFINE_TOKEN(Cdo, (kCDOToken))
DEFINE_TOKEN(Cdc, (kCDCToken))
DEFINE_TOKEN(LeftParenthesis, (kLeftParenthesisToken))
DEFINE_TOKEN(RightParenthesis, (kRightParenthesisToken))
DEFINE_TOKEN(LeftBracket, (kLeftBracketToken))
DEFINE_TOKEN(RightBracket, (kRightBracketToken))
DEFINE_TOKEN(LeftBrace, (kLeftBraceToken))
DEFINE_TOKEN(RightBrace, (kRightBraceToken))
DEFINE_TOKEN(BadString, (kBadStringToken))
DEFINE_TOKEN(BadUrl, (kBadUrlToken))

#undef DEFINE_TOKEN

String FromUChar32(UChar32 c) {
  StringBuilder input;
  input.Append(c);
  return input.ToString();
}

TEST(CSSTokenizerTest, SingleCharacterTokens) {
  TEST_TOKENS("(", LeftParenthesis());
  TEST_TOKENS(")", RightParenthesis());
  TEST_TOKENS("[", LeftBracket());
  TEST_TOKENS("]", RightBracket());
  TEST_TOKENS(",", Comma());
  TEST_TOKENS(":", Colon());
  TEST_TOKENS(";", Semicolon());
  TEST_TOKENS(")[", RightParenthesis(), LeftBracket());
  TEST_TOKENS("[)", LeftBracket(), RightParenthesis());
  TEST_TOKENS("{}", LeftBrace(), RightBrace());
  TEST_TOKENS(",,", Comma(), Comma());
}

TEST(CSSTokenizerTest, MultipleCharacterTokens) {
  TEST_TOKENS("~=", IncludeMatch());
  TEST_TOKENS("|=", DashMatch());
  TEST_TOKENS("^=", PrefixMatch());
  TEST_TOKENS("$=", SuffixMatch());
  TEST_TOKENS("*=", SubstringMatch());
  TEST_TOKENS("||", Column());
  TEST_TOKENS("|||", Column(), Delim('|'));
  TEST_TOKENS("<!--", Cdo());
  TEST_TOKENS("<!---", Cdo(), Delim('-'));
  TEST_TOKENS("-->", Cdc());
}

TEST(CSSTokenizerTest, DelimiterToken) {
  TEST_TOKENS("^", Delim('^'));
  TEST_TOKENS("*", Delim('*'));
  TEST_TOKENS("%", Delim('%'));
  TEST_TOKENS("~", Delim('~'));
  TEST_TOKENS("|", Delim('|'));
  TEST_TOKENS("&", Delim('&'));
  TEST_TOKENS("\x7f", Delim('\x7f'));
  TEST_TOKENS("\1", Delim('\x1'));
  TEST_TOKENS("~-", Delim('~'), Delim('-'));
  TEST_TOKENS("^|", Delim('^'), Delim('|'));
  TEST_TOKENS("$~", Delim('$'), Delim('~'));
  TEST_TOKENS("*^", Delim('*'), Delim('^'));
}

TEST(CSSTokenizerTest, WhitespaceTokens) {
  TEST_TOKENS("   ", Whitespace());
  TEST_TOKENS("\n\rS", Whitespace(), Ident("S"));
  TEST_TOKENS("   *", Whitespace(), Delim('*'));
  TEST_TOKENS("\r\n\f\t2", Whitespace(), Number(kIntegerValueType, 2, kNoSign));
}

TEST(CSSTokenizerTest, Escapes) {
  TEST_TOKENS("hel\\6Co", Ident("hello"));
  TEST_TOKENS("\\26 B", Ident("&B"));
  TEST_TOKENS("'hel\\6c o'", GetString("hello"));
  TEST_TOKENS("'spac\\65\r\ns'", GetString("spaces"));
  TEST_TOKENS("spac\\65\r\ns", Ident("spaces"));
  TEST_TOKENS("spac\\65\n\rs", Ident("space"), Whitespace(), Ident("s"));
  TEST_TOKENS("sp\\61\tc\\65\fs", Ident("spaces"));
  TEST_TOKENS("hel\\6c  o", Ident("hell"), Whitespace(), Ident("o"));
  TEST_TOKENS("test\\\n", Ident("test"), Delim('\\'), Whitespace());
  TEST_TOKENS("test\\D799", Ident("test" + FromUChar32(0xD799)));
  TEST_TOKENS("\\E000", Ident(FromUChar32(0xE000)));
  TEST_TOKENS("te\\s\\t", Ident("test"));
  TEST_TOKENS("spaces\\ in\\\tident", Ident("spaces in\tident"));
  TEST_TOKENS("\\.\\,\\:\\!", Ident(".,:!"));
  TEST_TOKENS("\\\r", Delim('\\'), Whitespace());
  TEST_TOKENS("\\\f", Delim('\\'), Whitespace());
  TEST_TOKENS("\\\r\n", Delim('\\'), Whitespace());
  String replacement = FromUChar32(0xFFFD);
  TEST_TOKENS(String(base::span_from_cstring("null\\\0")),
              Ident("null" + replacement));
  TEST_TOKENS(String(base::span_from_cstring("null\\\0\0")),
              Ident("null" + replacement + replacement));
  TEST_TOKENS("null\\0", Ident("null" + replacement));
  TEST_TOKENS("null\\0000", Ident("null" + replacement));
  TEST_TOKENS("large\\110000", Ident("large" + replacement));
  TEST_TOKENS("large\\23456a", Ident("large" + replacement));
  TEST_TOKENS("surrogate\\D800", Ident("surrogate" + replacement));
  TEST_TOKENS("surrogate\\0DABC", Ident("surrogate" + replacement));
  TEST_TOKENS("\\00DFFFsurrogate", Ident(replacement + "surrogate"));
  TEST_TOKENS("\\10fFfF", Ident(FromUChar32(0x10ffff)));
  TEST_TOKENS("\\10fFfF0", Ident(FromUChar32(0x10ffff) + "0"));
  TEST_TOKENS("\\10000000", Ident(FromUChar32(0x100000) + "00"));
  TEST_TOKENS("eof\\", Ident("eof" + replacement));
}

TEST(CSSTokenizerTest, IdentToken) {
  TEST_TOKENS("simple-ident", Ident("simple-ident"));
  TEST_TOKENS("testing123", Ident("testing123"));
  TEST_TOKENS("hello!", Ident("hello"), Delim('!'));
  TEST_TOKENS("world\5", Ident("world"), Delim('\5'));
  TEST_TOKENS("_under score", Ident("_under"), Whitespace(), Ident("score"));
  TEST_TOKENS("-_underscore", Ident("-_underscore"));
  TEST_TOKENS("-text", Ident("-text"));
  TEST_TOKENS("-\\6d", Ident("-m"));
  TEST_TOKENS("--abc", Ident("--abc"));
  TEST_TOKENS("--", Ident("--"));
  TEST_TOKENS("--11", Ident("--11"));
  TEST_TOKENS("---", Ident("---"));
  TEST_TOKENS(FromUChar32(0x2003), Ident(FromUChar32(0x2003)));  // em-space
  TEST_TOKENS(FromUChar32(0xA0),
              Ident(FromUChar32(0xA0)));  // non-breaking space
  TEST_TOKENS(FromUChar32(0x1234), Ident(FromUChar32(0x1234)));
  TEST_TOKENS(FromUChar32(0x12345), Ident(FromUChar32(0x12345)));
  TEST_TOKENS(String(base::span_from_cstring("\0")),
              Ident(FromUChar32(0xFFFD)));
  TEST_TOKENS(String(base::span_from_cstring("ab\0c")),
              Ident("ab" + FromUChar32(0xFFFD) + "c"));
  TEST_TOKENS(String(base::span_from_cstring("ab\0c")),
              Ident("ab" + FromUChar32(0xFFFD) + "c"));
}

TEST(CSSTokenizerTest, FunctionToken) {
  TEST_TOKENS("scale(2)", Func("scale"), Number(kIntegerValueType, 2, kNoSign),
              RightParenthesis());
  TEST_TOKENS("foo-bar\\ baz(", Func("foo-bar baz"));
  TEST_TOKENS("fun\\(ction(", Func("fun(ction"));
  TEST_TOKENS("-foo(", Func("-foo"));
  TEST_TOKENS("url(\"foo.gif\"", Func("url"), GetString("foo.gif"));
  TEST_TOKENS("foo(  \'bar.gif\'", Func("foo"), Whitespace(),
              GetString("bar.gif"));
  // To simplify implementation we drop the whitespace in
  // function(url),whitespace,string()
  TEST_TOKENS("url(  \'bar.gif\'", Func("url"), GetString("bar.gif"));
}

TEST(CSSTokenizerTest, AtKeywordToken) {
  TEST_TOKENS("@at-keyword", AtKeyword("at-keyword"));
  TEST_TOKENS("@testing123", AtKeyword("testing123"));
  TEST_TOKENS("@hello!", AtKeyword("hello"), Delim('!'));
  TEST_TOKENS("@-text", AtKeyword("-text"));
  TEST_TOKENS("@--abc", AtKeyword("--abc"));
  TEST_TOKENS("@--", AtKeyword("--"));
  TEST_TOKENS("@--11", AtKeyword("--11"));
  TEST_TOKENS("@---", AtKeyword("---"));
  TEST_TOKENS("@\\ ", AtKeyword(" "));
  TEST_TOKENS("@-\\ ", AtKeyword("- "));
  TEST_TOKENS("@@", Delim('@'), Delim('@'));
  TEST_TOKENS("@2", Delim('@'), Number(kIntegerValueType, 2, kNoSign));
  TEST_TOKENS("@-1", Delim('@'), Number(kIntegerValueType, -1, kMinusSign));
}

TEST(CSSTokenizerTest, UrlToken) {
  TEST_TOKENS("url(foo.gif)", Url("foo.gif"));
  TEST_TOKENS("urL(https://example.com/cats.png)",
              Url("https://example.com/cats.png"));
  TEST_TOKENS("uRl(what-a.crazy^URL~this\\ is!)",
              Url("what-a.crazy^URL~this is!"));
  TEST_TOKENS("uRL(123#test)", Url("123#test"));
  TEST_TOKENS("Url(escapes\\ \\\"\\'\\)\\()", Url("escapes \"')("));
  TEST_TOKENS("UrL(   whitespace   )", Url("whitespace"));
  TEST_TOKENS("URl( whitespace-eof ", Url("whitespace-eof"));
  TEST_TOKENS("URL(eof", Url("eof"));
  TEST_TOKENS("url(not/*a*/comment)", Url("not/*a*/comment"));
  TEST_TOKENS("urL()", Url(""));
  TEST_TOKENS("uRl(white space),", BadUrl(), Comma());
  TEST_TOKENS("Url(b(ad),", BadUrl(), Comma());
  TEST_TOKENS("uRl(ba'd):", BadUrl(), Colon());
  TEST_TOKENS("urL(b\"ad):", BadUrl(), Colon());
  TEST_TOKENS("uRl(b\"ad):", BadUrl(), Colon());
  TEST_TOKENS("Url(b\\\rad):", BadUrl(), Colon());
  TEST_TOKENS("url(b\\\nad):", BadUrl(), Colon());
  TEST_TOKENS("url(/*'bad')*/", BadUrl(), Delim('*'), Delim('/'));
  TEST_TOKENS("url(ba'd\\\\))", BadUrl(), RightParenthesis());
}

TEST(CSSTokenizerTest, StringToken) {
  TEST_TOKENS("'text'", GetString("text"));
  TEST_TOKENS("\"text\"", GetString("text"));
  TEST_TOKENS("'testing, 123!'", GetString("testing, 123!"));
  TEST_TOKENS("'es\\'ca\\\"pe'", GetString("es'ca\"pe"));
  TEST_TOKENS("'\"quotes\"'", GetString("\"quotes\""));
  TEST_TOKENS("\"'quotes'\"", GetString("'quotes'"));
  TEST_TOKENS("\"mismatch'", GetString("mismatch'"));
  TEST_TOKENS("'text\5\t\13'", GetString("text\5\t\13"));
  TEST_TOKENS("\"end on eof", GetString("end on eof"));
  TEST_TOKENS("'esca\\\nped'", GetString("escaped"));
  TEST_TOKENS("\"esc\\\faped\"", GetString("escaped"));
  TEST_TOKENS("'new\\\rline'", GetString("newline"));
  TEST_TOKENS("\"new\\\r\nline\"", GetString("newline"));
  TEST_TOKENS("'bad\nstring", BadString(), Whitespace(), Ident("string"));
  TEST_TOKENS("'bad\rstring", BadString(), Whitespace(), Ident("string"));
  TEST_TOKENS("'bad\r\nstring", BadString(), Whitespace(), Ident("string"));
  TEST_TOKENS("'bad\fstring", BadString(), Whitespace(), Ident("string"));
  TEST_TOKENS(String(base::span_from_cstring("'\0'")),
              GetString(FromUChar32(0xFFFD)));
  TEST_TOKENS(String(base::span_from_cstring("'hel\0lo'")),
              GetString("hel" + FromUChar32(0xFFFD) + "lo"));
  TEST_TOKENS(String(base::span_from_cstring("'h\\65l\0lo'")),
              GetString("hel" + FromUChar32(0xFFFD) + "lo"));
}

TEST(CSSTokenizerTest, HashToken) {
  TEST_TOKENS("#id-selector", GetHash("id-selector", kHashTokenId));
  TEST_TOKENS("#FF7700", GetHash("FF7700", kHashTokenId));
  TEST_TOKENS("#3377FF", GetHash("3377FF", kHashTokenUnrestricted));
  TEST_TOKENS("#\\ ", GetHash(" ", kHashTokenId));
  TEST_TOKENS("# ", Delim('#'), Whitespace());
  TEST_TOKENS("#\\\n", Delim('#'), Delim('\\'), Whitespace());
  TEST_TOKENS("#\\\r\n", Delim('#'), Delim('\\'), Whitespace());
  TEST_TOKENS("#!", Delim('#'), Delim('!'));
}

TEST(CSSTokenizerTest, NumberToken) {
  TEST_TOKENS("10", Number(kIntegerValueType, 10, kNoSign));
  TEST_TOKENS("12.0", Number(kNumberValueType, 12, kNoSign));
  TEST_TOKENS("+45.6", Number(kNumberValueType, 45.6, kPlusSign));
  TEST_TOKENS("-7", Number(kIntegerValueType, -7, kMinusSign));
  TEST_TOKENS("010", Number(kIntegerValueType, 10, kNoSign));
  TEST_TOKENS("10e0", Number(kNumberValueType, 10, kNoSign));
  TEST_TOKENS("12e3", Number(kNumberValueType, 12000, kNoSign));
  TEST_TOKENS("3e+1", Number(kNumberValueType, 30, kNoSign));
  TEST_TOKENS("12E-1", Number(kNumberValueType, 1.2, kNoSign));
  TEST_TOKENS(".7", Number(kNumberValueType, 0.7, kNoSign));
  TEST_TOKENS("-.3", Number(kNumberValueType, -0.3, kMinusSign));
  TEST_TOKENS("+637.54e-2", Number(kNumberValueType, 6.3754, kPlusSign));
  TEST_TOKENS("-12.34E+2", Number(kNumberValueType, -1234, kMinusSign));

  TEST_TOKENS("+ 5", Delim('+'), Whitespace(),
              Number(kIntegerValueType, 5, kNoSign));
  TEST_TOKENS("-+12", Delim('-'), Number(kIntegerValueType, 12, kPlusSign));
  TEST_TOKENS("+-21", Delim('+'), Number(kIntegerValueType, -21, kMinusSign));
  TEST_TOKENS("++22", Delim('+'), Number(kIntegerValueType, 22, kPlusSign));
  TEST_TOKENS("13.", Number(kIntegerValueType, 13, kNoSign), Delim('.'));
  TEST_TOKENS("1.e2", Number(kIntegerValueType, 1, kNoSign), Delim('.'),
              Ident("e2"));
  TEST_TOKENS("2e3.5", Number(kNumberValueType, 2000, kNoSign),
              Number(kNumberValueType, 0.5, kNoSign));
  TEST_TOKENS("2e3.", Number(kNumberValueType, 2000, kNoSign), Delim('.'));
  TEST_TOKENS("1000000000000000000000000",
              Number(kIntegerValueType, 1e24, kNoSign));
}

TEST(CSSTokenizerTest, DimensionToken) {
  TEST_TOKENS("10px", Dimension(kIntegerValueType, 10, "px"));
  TEST_TOKENS("12.0em", Dimension(kNumberValueType, 12, "em"));
  TEST_TOKENS("-12.0em", Dimension(kNumberValueType, -12, "em"));
  TEST_TOKENS("+45.6__qem", Dimension(kNumberValueType, 45.6, "__qem"));
  TEST_TOKENS("5e", Dimension(kIntegerValueType, 5, "e"));
  TEST_TOKENS("5px-2px", Dimension(kIntegerValueType, 5, "px-2px"));
  TEST_TOKENS("5e-", Dimension(kIntegerValueType, 5, "e-"));
  TEST_TOKENS("5\\ ", Dimension(kIntegerValueType, 5, " "));
  TEST_TOKENS("40\\70\\78", Dimension(kIntegerValueType, 40, "px"));
  TEST_TOKENS("4e3e2", Dimension(kNumberValueType, 4000, "e2"));
  TEST_TOKENS("0x10px", Dimension(kIntegerValueType, 0, "x10px"));
  TEST_TOKENS("4unit ", Dimension(kIntegerValueType, 4, "unit"), Whitespace());
  TEST_TOKENS("5e+", Dimension(kIntegerValueType, 5, "e"), Delim('+'));
  TEST_TOKENS("2e.5", Dimension(kIntegerValueType, 2, "e"),
              Number(kNumberValueType, 0.5, kNoSign));
  TEST_TOKENS("2e+.5", Dimension(kIntegerValueType, 2, "e"),
              Number(kNumberValueType, 0.5, kPlusSign));
}

TEST(CSSTokenizerTest, PercentageToken) {
  TEST_TOKENS("10%", Percentage(kIntegerValueType, 10));
  TEST_TOKENS("+12.0%", Percentage(kNumberValueType, 12));
  TEST_TOKENS("-48.99%", Percentage(kNumberValueType, -48.99));
  TEST_TOKENS("6e-1%", Percentage(kNumberValueType, 0.6));
  TEST_TOKENS("5%%", Percentage(kIntegerValueType, 5), Delim('%'));
}

TEST(CSSTokenizerTest, UnicodeRangeToken) {
  TestUnicodeRangeTokens("u+012345-123456", UnicodeRng(0x012345, 0x123456));
  TestUnicodeRangeTokens("U+1234-2345", UnicodeRng(0x1234, 0x2345));
  TestUnicodeRangeTokens("u+222-111", UnicodeRng(0x222, 0x111));
  TestUnicodeRangeTokens("U+CafE-d00D", UnicodeRng(0xcafe, 0xd00d));
  TestUnicodeRangeTokens("U+2??", UnicodeRng(0x200, 0x2ff));
  TestUnicodeRangeTokens("U+ab12??", UnicodeRng(0xab1200, 0xab12ff));
  TestUnicodeRangeTokens("u+??????", UnicodeRng(0x000000, 0xffffff));
  TestUnicodeRangeTokens("u+??", UnicodeRng(0x00, 0xff));

  TestUnicodeRangeTokens("u+222+111", UnicodeRng(0x222, 0x222),
                         Number(kIntegerValueType, 111, kPlusSign));
  TestUnicodeRangeTokens("u+12345678", UnicodeRng(0x123456, 0x123456),
                         Number(kIntegerValueType, 78, kNoSign));
  TestUnicodeRangeTokens("u+123-12345678", UnicodeRng(0x123, 0x123456),
                         Number(kIntegerValueType, 78, kNoSign));
  TestUnicodeRangeTokens("u+cake", UnicodeRng(0xca, 0xca), Ident("ke"));
  TestUnicodeRangeTokens("u+1234-gggg", UnicodeRng(0x1234, 0x1234),
                         Ident("-gggg"));
  TestUnicodeRangeTokens("U+ab12???", UnicodeRng(0xab1200, 0xab12ff),
                         Delim('?'));
  TestUnicodeRangeTokens("u+a1?-123", UnicodeRng(0xa10, 0xa1f),
                         Number(kIntegerValueType, -123, kMinusSign));
  TestUnicodeRangeTokens("u+1??4", UnicodeRng(0x100, 0x1ff),
                         Number(kIntegerValueType, 4, kNoSign));
  TEST_TOKENS("u+z", Ident("u"), Delim('+'), Ident("z"));
  TEST_TOKENS("u+", Ident("u"), Delim('+'));
  TEST_TOKENS("u+-543", Ident("u"), Delim('+'),
              Number(kIntegerValueType, -543, kMinusSign));

  TEST_TOKENS("u+012345", Ident("u"),
              Number(kIntegerValueType, 12345, kPlusSign));
  TEST_TOKENS("u+a", Ident("u"), Delim('+'), Ident("a"));
  TestUnicodeRangeTokens("u+a", UnicodeRng(0xa, 0xa));
}

TEST(CSSTokenizerTest, CommentToken) {
  TEST_TOKENS("/*comment*/a", Ident("a"));
  TEST_TOKENS("/**\\2f**//", Delim('/'));
  TEST_TOKENS("/**y*a*y**/ ", Whitespace());
  TEST_TOKENS(",/* \n :) \n */)", Comma(), RightParenthesis());
  TEST_TOKENS(":/*/*/", Colon());
  TEST_TOKENS("/**/*", Delim('*'));
  TEST_TOKENS(";/******", Semicolon());
}

}  // namespace blink
```