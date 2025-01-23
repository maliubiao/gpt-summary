Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Understand the Goal:** The request is to analyze a specific V8 source file (`scanner-inl.h`) and describe its functionality, relate it to JavaScript, provide code logic examples, and highlight potential user errors.

2. **Initial Scan and Keywords:**  Quickly read through the file, looking for recognizable keywords and patterns. Notice:
    * `#ifndef`, `#define`, `#include`: Standard C++ header file guards and inclusions.
    * `namespace v8 { namespace internal {`:  Indicates this is part of V8's internal implementation.
    * `// Copyright ...`:  Standard copyright notice.
    * `KEYWORDS(...)`: This looks like a macro defining a list of keywords. This is a strong clue about the file's purpose.
    * `Token::k...`:  Enumerated values likely representing different types of tokens.
    * `IsKeywordStart`, `KeywordOrIdentifierToken`, `CanBeKeywordCharacter`: Function names suggesting the file deals with identifying keywords and identifiers.
    * `GetOneCharToken`: Suggests handling single-character tokens.
    * `Scanner::Scan...`: Methods within a `Scanner` class, hinting at a lexical analysis process.

3. **Identify Core Functionality (Lexical Analysis/Scanning):** Based on the keywords, function names, and the file path (`parsing/scanner-inl.h`), it becomes clear that this file is a crucial part of V8's *scanner*. The scanner's job is to perform *lexical analysis*, which is the first stage of compilation. It breaks down the raw input (JavaScript code) into a stream of meaningful tokens.

4. **Analyze the `KEYWORDS` Macro:**  This macro is central. It lists all the JavaScript keywords and associates them with `Token::k...` values. This confirms the file's role in keyword recognition. Notice the grouping by starting letter – this is likely an optimization for faster lookup.

5. **Examine Key Functions:**
    * `IsKeywordStart`:  Determines if a character can start a keyword.
    * `KeywordOrIdentifierToken`: Given a sequence of characters, it checks if it's a keyword and returns the corresponding token, or if it's an identifier. The use of `PerfectKeywordHash` suggests an optimization for fast keyword lookup.
    * `GetOneCharToken`:  Maps single characters to their corresponding token values (operators, punctuation, etc.).
    * `Scanner::ScanIdentifierOrKeyword`:  Handles the more complex case of identifying sequences that could be either keywords or identifiers. It includes fast-path and slow-path logic, likely for performance.
    * `Scanner::SkipWhiteSpace`:  Handles the removal of whitespace.
    * `Scanner::ScanSingleToken`: The main entry point for scanning. It uses the `one_char_tokens` table for quick lookup and then handles more complex cases (operators, strings, comments, etc.).
    * `Scanner::Scan`:  The public interface to initiate scanning.

6. **Relate to JavaScript Functionality:**  The keywords listed directly correspond to JavaScript keywords. The single-character tokens are the basic building blocks of JavaScript syntax. The scanner is the *first* step in understanding JavaScript code. It doesn't understand the *meaning* of the code, just the individual units.

7. **Provide JavaScript Examples:**  Illustrate the keywords and single-character tokens in context. Show how they are used in valid JavaScript code.

8. **Infer Code Logic (Assumptions and Outputs):**  Focus on the `ScanIdentifierOrKeyword` and `ScanSingleToken` functions. Make assumptions about the input (e.g., starting with a letter, starting with a single-character operator). Trace mentally or with simple examples how these functions might process the input and what token they would output.

9. **Identify Common Programming Errors:** Think about the errors that a *scanner* would be able to detect. Invalid characters, unterminated strings, incorrect use of operators – these are common syntax errors that the scanner would flag. Provide concrete JavaScript examples of these errors.

10. **Address `.tq` Extension:** Explain that `.tq` indicates Torque code, a V8-specific language, and that this file uses `.h`, meaning it's standard C++.

11. **Structure the Answer:** Organize the findings logically into sections: Functionality, Relationship to JavaScript, Code Logic, Common Errors, and Torque explanation. Use clear and concise language. Use code blocks to illustrate examples.

12. **Review and Refine:**  Read through the answer to ensure accuracy, clarity, and completeness. Check for any missing information or areas that could be explained better. For instance, initially, I might not have emphasized the "first step" aspect of the scanner strongly enough, so I'd refine that during review. I might also add more detail about the purpose of the fast and slow paths in `ScanIdentifierOrKeyword`.

By following these steps, we can systematically analyze the provided C++ header file and generate a comprehensive and informative response. The key is to start with the obvious clues (file path, keywords) and then delve deeper into the code structure and function names to understand the underlying mechanisms.
## 功能列举：

`v8/src/parsing/scanner-inl.h` 是 V8 引擎中词法分析器（Scanner）的内联实现头文件。它的主要功能是定义并实现了词法分析的关键步骤，负责将输入的源代码字符流分解成一系列有意义的词法单元（tokens）。

具体来说，这个文件实现了以下功能：

1. **定义和识别关键字 (Keywords)：**
   - 通过 `KEYWORDS` 宏定义了所有 JavaScript 的关键字，例如 `if`, `else`, `function`, `class` 等，并将它们与对应的 `Token::k...` 枚举值关联起来。
   - 提供了 `IsKeywordStart(char c)` 函数，用于判断一个字符是否可以作为关键字的开头。
   - 提供了 `KeywordOrIdentifierToken(const uint8_t* input, int input_length)` 函数，用于判断一段字符序列是关键字还是标识符，并返回相应的 Token 值。

2. **识别单字符 Token：**
   - 定义了 `GetOneCharToken(char c)` 函数，用于将单个字符映射到对应的 Token 值，例如 `(` 映射到 `Token::kLeftParen`。
   - 使用 `one_char_tokens` 数组作为查找表，快速获取单字符的 Token 值。

3. **识别标识符 (Identifiers)：**
   - 提供了 `ScanIdentifierOrKeyword()` 和 `ScanIdentifierOrKeywordInner()` 函数来扫描标识符。这些函数会读取连续的标识符字符，并根据是否与关键字匹配来返回 `Token::kIdentifier` 或相应的关键字 Token。
   - 考虑了 Unicode 转义字符的情况。

4. **跳过空白符 (Whitespace)：**
   - 提供了 `SkipWhiteSpace()` 函数，用于跳过源代码中的空格、制表符、换行符等空白字符。

5. **扫描单个 Token：**
   - `ScanSingleToken()` 函数是扫描器的核心，负责从当前位置开始扫描并识别下一个 Token。
   - 它会根据当前字符判断 Token 类型，并调用相应的子函数进行更详细的扫描，例如：
     - 扫描字符串 (`ScanString()`)
     - 扫描数字 (`ScanNumber()`)
     - 扫描模板字符串 (`ScanTemplateSpan()`)
     - 扫描私有名称 (`ScanPrivateName()`)
     - 扫描各种运算符 (如 `+`, `-`, `*`, `/`, `=`, `<`, `>`, `&`, `|`, `^`)
     - 扫描注释 (`SkipSingleLineComment()`, `SkipMultiLineComment()`, `ScanHtmlComment()`)

6. **处理特殊情况：**
   - 处理 HTML 注释 (`<!--`) 和单行 HTML 注释结束符 (`-->`)。
   - 处理 Nullish 合并运算符 (`??`) 和可选链运算符 (`?.`).
   - 处理指数运算符 (`**`).
   - 处理魔法注释 (`//#` 或 `//@`).

7. **辅助函数和常量：**
   - `CanBeKeywordCharacter(char c)` 判断字符是否可以出现在关键字中。
   - `IsAsciiIdentifier(c)` 等函数用于判断字符的类型。
   - `character_scan_flags` 数组用于快速判断字符的属性，优化扫描速度。

8. **`Scanner` 类：**
   -  这个 `.inl.h` 文件是 `Scanner` 类的一部分（内联实现），包含了 `Scanner` 类的一些核心方法的实现。

**如果 `v8/src/parsing/scanner-inl.h` 以 `.tq` 结尾:**

如果 `v8/src/parsing/scanner-inl.h` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是 V8 自研的一种用于编写高效运行时代码的语言。在这种情况下，该文件将包含用 Torque 编写的词法分析器实现。Torque 代码会被编译成 C++ 代码。

**与 JavaScript 功能的关系 (并用 JavaScript 举例说明):**

`v8/src/parsing/scanner-inl.h` 与 JavaScript 功能 **密切相关**。词法分析是 JavaScript 引擎编译和执行 JavaScript 代码的第一步。它将我们编写的文本形式的 JavaScript 代码转换成引擎可以理解的 Token 流。

**JavaScript 例子:**

考虑以下简单的 JavaScript 代码片段：

```javascript
function add(a, b) {
  return a + b;
}
```

`v8/src/parsing/scanner-inl.h` 中定义的扫描器会将其分解成以下 Token 流（简化表示）：

- `function` (Token::kFunction)
- `add` (Token::kIdentifier)
- `(` (Token::kLeftParen)
- `a` (Token::kIdentifier)
- `,` (Token::kComma)
- `b` (Token::kIdentifier)
- `)` (Token::kRightParen)
- `{` (Token::kLeftBrace)
- `return` (Token::kReturn)
- `a` (Token::kIdentifier)
- `+` (Token::kAdd)
- `b` (Token::kIdentifier)
- `;` (Token::kSemicolon)
- `}` (Token::kRightBrace)

**代码逻辑推理 (假设输入与输出):**

**假设输入 (字符串):** `"while (count < 10) {"`

**扫描过程 (简化):**

1. **'w'**: `IsKeywordStart('w')` 返回 true。扫描器读取 "while"。
2. **"while"**: `KeywordOrIdentifierToken("while", 5)` 返回 `Token::kWhile`。
3. **' '**: `SkipWhiteSpace()` 跳过空格。
4. **'('**: `GetOneCharToken('(')` 返回 `Token::kLeftParen`。
5. **'c'**: `IsKeywordStart('c')` 返回 false。扫描器读取 "count"。
6. **"count"**: `KeywordOrIdentifierToken("count", 5)` 返回 `Token::kIdentifier`。
7. **' '**: `SkipWhiteSpace()` 跳过空格。
8. **'<'**: `GetOneCharToken('<')` 返回 `Token::kLessThan`。
9. **' '**: `SkipWhiteSpace()` 跳过空格。
10. **'1'**: `IsDecimalDigit('1')` 返回 true。扫描器读取 "10"。
11. **"10"**: 扫描数字，返回 `Token::kNumber`。
12. **')'**: `GetOneCharToken(')')` 返回 `Token::kRightParen`。
13. **' '**: `SkipWhiteSpace()` 跳过空格。
14. **'{'**: `GetOneCharToken('{')` 返回 `Token::kLeftBrace`。

**假设输出 (Token 序列):** `Token::kWhile`, `Token::kLeftParen`, `Token::kIdentifier`, `Token::kLessThan`, `Token::kNumber`, `Token::kRightParen`, `Token::kLeftBrace`

**涉及用户常见的编程错误 (并举例说明):**

扫描器是第一个处理源代码的阶段，它可以检测到一些基本的语法错误。

1. **拼写错误的关键字:**

   ```javascript
   functoin myFunction() { // 错误拼写 "function"
     console.log("Hello");
   }
   ```

   扫描器会尝试将 "functoin" 识别为关键字，但由于拼写错误，`KeywordOrIdentifierToken("functoin", ...)` 不会匹配任何关键字，最终可能被识别为 `Token::kIdentifier`，但这会在后续的语法分析阶段导致错误。

2. **未闭合的字符串:**

   ```javascript
   const message = "Hello; // 缺少结尾的引号
   ```

   当扫描器遇到开始的引号 `"` 时，会进入字符串扫描模式。如果没有找到匹配的结尾引号，扫描器会报错，因为它无法确定字符串的结束位置。这会导致生成 `Token::kIllegal` 或类似的错误 Token。

3. **使用了非法字符:**

   ```javascript
   let x = 1 + $; // '$' 在这里是非法字符
   ```

   扫描器会检查每个字符是否属于合法的 Token 组成部分。如果遇到无法识别的字符（除非是字符串内部），例如上面例子中的 `$`, 扫描器会返回 `Token::kIllegal`。

4. **数字格式错误:**

   ```javascript
   let num = 1..2; // 错误的浮点数表示
   ```

   扫描器在扫描数字时，会根据数字的语法规则进行解析。像 `1..2` 这样的结构会被识别为 `Token::kNumber` (1) 紧跟着 `Token::kPeriod` (.) 再跟着一个 `Token::kNumber` (2)，这可能不是用户的预期，并会在后续阶段导致错误。

5. **注释未闭合 (多行注释):**

   ```javascript
   /*
   这是一个
   多行注释
   ```

   如果多行注释 `/*` 没有对应的 `*/` 结尾，扫描器会一直扫描到文件末尾，并可能报错，因为它期望找到注释的结束符。

总而言之，`v8/src/parsing/scanner-inl.h` 文件是 V8 引擎中词法分析器的核心组成部分，它定义了如何将 JavaScript 源代码分解成 Token，为后续的语法分析和代码生成奠定了基础。它直接影响着 V8 引擎对 JavaScript 代码的理解和处理。

### 提示词
```
这是目录为v8/src/parsing/scanner-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/parsing/scanner-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_PARSING_SCANNER_INL_H_
#define V8_PARSING_SCANNER_INL_H_

#include "src/parsing/keywords-gen.h"
#include "src/parsing/scanner.h"
#include "src/strings/char-predicates-inl.h"
#include "src/utils/utils.h"

namespace v8 {
namespace internal {

// ----------------------------------------------------------------------------
// Keyword Matcher

#define KEYWORDS(KEYWORD_GROUP, KEYWORD)                  \
  KEYWORD_GROUP('a')                                      \
  KEYWORD("async", Token::kAsync)                         \
  KEYWORD("await", Token::kAwait)                         \
  KEYWORD_GROUP('b')                                      \
  KEYWORD("break", Token::kBreak)                         \
  KEYWORD_GROUP('c')                                      \
  KEYWORD("case", Token::kCase)                           \
  KEYWORD("catch", Token::kCatch)                         \
  KEYWORD("class", Token::kClass)                         \
  KEYWORD("const", Token::kConst)                         \
  KEYWORD("continue", Token::kContinue)                   \
  KEYWORD_GROUP('d')                                      \
  KEYWORD("debugger", Token::kDebugger)                   \
  KEYWORD("default", Token::kDefault)                     \
  KEYWORD("delete", Token::kDelete)                       \
  KEYWORD("do", Token::kDo)                               \
  KEYWORD_GROUP('e')                                      \
  KEYWORD("else", Token::kElse)                           \
  KEYWORD("enum", Token::kEnum)                           \
  KEYWORD("export", Token::kExport)                       \
  KEYWORD("extends", Token::kExtends)                     \
  KEYWORD_GROUP('f')                                      \
  KEYWORD("false", Token::kFalseLiteral)                  \
  KEYWORD("finally", Token::kFinally)                     \
  KEYWORD("for", Token::kFor)                             \
  KEYWORD("function", Token::kFunction)                   \
  KEYWORD_GROUP('g')                                      \
  KEYWORD("get", Token::kGet)                             \
  KEYWORD_GROUP('i')                                      \
  KEYWORD("if", Token::kIf)                               \
  KEYWORD("implements", Token::kFutureStrictReservedWord) \
  KEYWORD("import", Token::kImport)                       \
  KEYWORD("in", Token::kIn)                               \
  KEYWORD("instanceof", Token::kInstanceOf)               \
  KEYWORD("interface", Token::kFutureStrictReservedWord)  \
  KEYWORD_GROUP('l')                                      \
  KEYWORD("let", Token::kLet)                             \
  KEYWORD_GROUP('n')                                      \
  KEYWORD("new", Token::kNew)                             \
  KEYWORD("null", Token::kNullLiteral)                    \
  KEYWORD_GROUP('o')                                      \
  KEYWORD("of", Token::kOf)                               \
  KEYWORD_GROUP('p')                                      \
  KEYWORD("package", Token::kFutureStrictReservedWord)    \
  KEYWORD("private", Token::kFutureStrictReservedWord)    \
  KEYWORD("protected", Token::kFutureStrictReservedWord)  \
  KEYWORD("public", Token::kFutureStrictReservedWord)     \
  KEYWORD_GROUP('r')                                      \
  KEYWORD("return", Token::kReturn)                       \
  KEYWORD_GROUP('s')                                      \
  KEYWORD("set", Token::kSet)                             \
  KEYWORD("static", Token::kStatic)                       \
  KEYWORD("super", Token::kSuper)                         \
  KEYWORD("switch", Token::kSwitch)                       \
  KEYWORD_GROUP('t')                                      \
  KEYWORD("this", Token::kThis)                           \
  KEYWORD("throw", Token::kThrow)                         \
  KEYWORD("true", Token::kTrueLiteral)                    \
  KEYWORD("try", Token::kTry)                             \
  KEYWORD("typeof", Token::kTypeOf)                       \
  KEYWORD_GROUP('u')                                      \
  KEYWORD("using", Token::kUsing)                         \
  KEYWORD_GROUP('v')                                      \
  KEYWORD("var", Token::kVar)                             \
  KEYWORD("void", Token::kVoid)                           \
  KEYWORD_GROUP('w')                                      \
  KEYWORD("while", Token::kWhile)                         \
  KEYWORD("with", Token::kWith)                           \
  KEYWORD_GROUP('y')                                      \
  KEYWORD("yield", Token::kYield)

constexpr bool IsKeywordStart(char c) {
#define KEYWORD_GROUP_CHECK(ch) c == ch ||
#define KEYWORD_CHECK(keyword, token)
  return KEYWORDS(KEYWORD_GROUP_CHECK, KEYWORD_CHECK) /* || */ false;
#undef KEYWORD_GROUP_CHECK
#undef KEYWORD_CHECK
}

V8_INLINE Token::Value KeywordOrIdentifierToken(const uint8_t* input,
                                                int input_length) {
  DCHECK_GE(input_length, 1);
  return PerfectKeywordHash::GetToken(reinterpret_cast<const char*>(input),
                                      input_length);
}

// Recursive constexpr template magic to check if a character is in a given
// string.
template <int N>
constexpr bool IsInString(const char (&s)[N], char c, size_t i = 0) {
  return i >= N ? false : s[i] == c ? true : IsInString(s, c, i + 1);
}

inline constexpr bool CanBeKeywordCharacter(char c) {
  return IsInString(
#define KEYWORD_GROUP_CASE(ch)  // Nothing
#define KEYWORD(keyword, token) keyword
      // Use C string literal concatenation ("a" "b" becomes "ab") to build one
      // giant string containing all the keywords.
      KEYWORDS(KEYWORD_GROUP_CASE, KEYWORD)
#undef KEYWORD
#undef KEYWORD_GROUP_CASE
          ,
      c);
}

// Make sure tokens are stored as a single byte.
static_assert(sizeof(Token::Value) == 1);

// Get the shortest token that this character starts, the token may change
// depending on subsequent characters.
constexpr Token::Value GetOneCharToken(char c) {
  // clang-format off
  return
      c == '(' ? Token::kLeftParen :
      c == ')' ? Token::kRightParen :
      c == '{' ? Token::kLeftBrace :
      c == '}' ? Token::kRightBrace :
      c == '[' ? Token::kLeftBracket :
      c == ']' ? Token::kRightBracket :
      c == '?' ? Token::kConditional :
      c == ':' ? Token::kColon :
      c == ';' ? Token::kSemicolon :
      c == ',' ? Token::kComma :
      c == '.' ? Token::kPeriod :
      c == '|' ? Token::kBitOr :
      c == '&' ? Token::kBitAnd :
      c == '^' ? Token::kBitXor :
      c == '~' ? Token::kBitNot :
      c == '!' ? Token::kNot :
      c == '<' ? Token::kLessThan :
      c == '>' ? Token::kGreaterThan :
      c == '%' ? Token::kMod :
      c == '=' ? Token::kAssign :
      c == '+' ? Token::kAdd :
      c == '-' ? Token::kSub :
      c == '*' ? Token::kMul :
      c == '/' ? Token::kDiv :
      c == '#' ? Token::kPrivateName :
      c == '"' ? Token::kString :
      c == '\'' ? Token::kString :
      c == '`' ? Token::kTemplateSpan :
      c == '\\' ? Token::kIdentifier :
      // Whitespace or line terminator
      c == ' ' ? Token::kWhitespace :
      c == '\t' ? Token::kWhitespace :
      c == '\v' ? Token::kWhitespace :
      c == '\f' ? Token::kWhitespace :
      c == '\r' ? Token::kWhitespace :
      c == '\n' ? Token::kWhitespace :
      // IsDecimalDigit must be tested before IsAsciiIdentifier
      IsDecimalDigit(c) ? Token::kNumber :
      IsAsciiIdentifier(c) ? Token::kIdentifier :
      Token::kIllegal;
  // clang-format on
}

// Table of one-character tokens, by character (0x00..0x7F only).
static const constexpr Token::Value one_char_tokens[128] = {
#define CALL_GET_SCAN_FLAGS(N) GetOneCharToken(N),
    INT_0_TO_127_LIST(CALL_GET_SCAN_FLAGS)
#undef CALL_GET_SCAN_FLAGS
};

#undef KEYWORDS

V8_INLINE Token::Value Scanner::ScanIdentifierOrKeyword() {
  next().literal_chars.Start();
  return ScanIdentifierOrKeywordInner();
}

// Character flags for the fast path of scanning a keyword or identifier token.
enum class ScanFlags : uint8_t {
  kTerminatesLiteral = 1 << 0,
  // "Cannot" rather than "can" so that this flag can be ORed together across
  // multiple characters.
  kCannotBeKeyword = 1 << 1,
  kCannotBeKeywordStart = 1 << 2,
  kStringTerminator = 1 << 3,
  kIdentifierNeedsSlowPath = 1 << 4,
  kMultilineCommentCharacterNeedsSlowPath = 1 << 5,
};
constexpr uint8_t GetScanFlags(char c) {
  return
      // Keywords are all lowercase and only contain letters.
      // Note that non-identifier characters do not set this flag, so
      // that it plays well with kTerminatesLiteral.
      (IsAsciiIdentifier(c) && !CanBeKeywordCharacter(c)
           ? static_cast<uint8_t>(ScanFlags::kCannotBeKeyword)
           : 0) |
      (IsKeywordStart(c)
           ? 0
           : static_cast<uint8_t>(ScanFlags::kCannotBeKeywordStart)) |
      // Anything that isn't an identifier character will terminate the
      // literal, or at least terminates the literal fast path processing
      // (like an escape).
      (!IsAsciiIdentifier(c)
           ? static_cast<uint8_t>(ScanFlags::kTerminatesLiteral)
           : 0) |
      // Possible string termination characters.
      ((c == '\'' || c == '"' || c == '\n' || c == '\r' || c == '\\')
           ? static_cast<uint8_t>(ScanFlags::kStringTerminator)
           : 0) |
      // Escapes are processed on the slow path.
      (c == '\\' ? static_cast<uint8_t>(ScanFlags::kIdentifierNeedsSlowPath)
                 : 0) |
      // Newlines and * are interesting characters for multiline comment
      // scanning.
      (c == '\n' || c == '\r' || c == '*'
           ? static_cast<uint8_t>(
                 ScanFlags::kMultilineCommentCharacterNeedsSlowPath)
           : 0);
}
inline bool TerminatesLiteral(uint8_t scan_flags) {
  return (scan_flags & static_cast<uint8_t>(ScanFlags::kTerminatesLiteral));
}
inline bool CanBeKeyword(uint8_t scan_flags) {
  return !(scan_flags & static_cast<uint8_t>(ScanFlags::kCannotBeKeyword));
}
inline bool IdentifierNeedsSlowPath(uint8_t scan_flags) {
  return (scan_flags &
          static_cast<uint8_t>(ScanFlags::kIdentifierNeedsSlowPath));
}
inline bool MultilineCommentCharacterNeedsSlowPath(uint8_t scan_flags) {
  return (scan_flags & static_cast<uint8_t>(
                           ScanFlags::kMultilineCommentCharacterNeedsSlowPath));
}
inline bool MayTerminateString(uint8_t scan_flags) {
  return (scan_flags & static_cast<uint8_t>(ScanFlags::kStringTerminator));
}
// Table of precomputed scan flags for the 128 ASCII characters, for branchless
// flag calculation during the scan.
static constexpr const uint8_t character_scan_flags[128] = {
#define CALL_GET_SCAN_FLAGS(N) GetScanFlags(N),
    INT_0_TO_127_LIST(CALL_GET_SCAN_FLAGS)
#undef CALL_GET_SCAN_FLAGS
};

inline bool CharCanBeKeyword(base::uc32 c) {
  return static_cast<uint32_t>(c) < arraysize(character_scan_flags) &&
         CanBeKeyword(character_scan_flags[c]);
}

V8_INLINE Token::Value Scanner::ScanIdentifierOrKeywordInner() {
  DCHECK(IsIdentifierStart(c0_));
  bool escaped = false;
  bool can_be_keyword = true;

  static_assert(arraysize(character_scan_flags) == kMaxAscii + 1);
  if (V8_LIKELY(static_cast<uint32_t>(c0_) <= kMaxAscii)) {
    if (V8_LIKELY(c0_ != '\\')) {
      uint8_t scan_flags = character_scan_flags[c0_];
      DCHECK(!TerminatesLiteral(scan_flags));
      static_assert(static_cast<uint8_t>(ScanFlags::kCannotBeKeywordStart) ==
                    static_cast<uint8_t>(ScanFlags::kCannotBeKeyword) << 1);
      scan_flags >>= 1;
      // Make sure the shifting above doesn't set IdentifierNeedsSlowPath.
      // Otherwise we'll fall into the slow path after scanning the identifier.
      DCHECK(!IdentifierNeedsSlowPath(scan_flags));
      AddLiteralChar(static_cast<char>(c0_));
      AdvanceUntil([this, &scan_flags](base::uc32 c0) {
        if (V8_UNLIKELY(static_cast<uint32_t>(c0) > kMaxAscii)) {
          // A non-ascii character means we need to drop through to the slow
          // path.
          // TODO(leszeks): This would be most efficient as a goto to the slow
          // path, check codegen and maybe use a bool instead.
          scan_flags |=
              static_cast<uint8_t>(ScanFlags::kIdentifierNeedsSlowPath);
          return true;
        }
        uint8_t char_flags = character_scan_flags[c0];
        scan_flags |= char_flags;
        if (TerminatesLiteral(char_flags)) {
          return true;
        } else {
          AddLiteralChar(static_cast<char>(c0));
          return false;
        }
      });

      if (V8_LIKELY(!IdentifierNeedsSlowPath(scan_flags))) {
        if (!CanBeKeyword(scan_flags)) return Token::kIdentifier;
        // Could be a keyword or identifier.
        base::Vector<const uint8_t> chars =
            next().literal_chars.one_byte_literal();
        return KeywordOrIdentifierToken(chars.begin(), chars.length());
      }

      can_be_keyword = CanBeKeyword(scan_flags);
    } else {
      // Special case for escapes at the start of an identifier.
      escaped = true;
      base::uc32 c = ScanIdentifierUnicodeEscape();
      DCHECK(!IsIdentifierStart(Invalid()));
      if (c == '\\' || !IsIdentifierStart(c)) {
        return Token::kIllegal;
      }
      AddLiteralChar(c);
      can_be_keyword = CharCanBeKeyword(c);
    }
  }

  return ScanIdentifierOrKeywordInnerSlow(escaped, can_be_keyword);
}

V8_INLINE Token::Value Scanner::SkipWhiteSpace() {
  if (!IsWhiteSpaceOrLineTerminator(c0_)) return Token::kIllegal;

  if (!next().after_line_terminator && unibrow::IsLineTerminator(c0_)) {
    next().after_line_terminator = true;
  }

  // Advance as long as character is a WhiteSpace or LineTerminator.
  base::uc32 hint = ' ';
  AdvanceUntil([this, &hint](base::uc32 c0) {
    if (V8_LIKELY(c0 == hint)) return false;
    if (IsWhiteSpaceOrLineTerminator(c0)) {
      if (!next().after_line_terminator && unibrow::IsLineTerminator(c0)) {
        next().after_line_terminator = true;
      }
      hint = c0;
      return false;
    }
    return true;
  });

  return Token::kWhitespace;
}

V8_INLINE Token::Value Scanner::ScanSingleToken() {
  Token::Value token;
  do {
    next().location.beg_pos = source_pos();

    if (V8_LIKELY(static_cast<unsigned>(c0_) <= kMaxAscii)) {
      token = one_char_tokens[c0_];

      switch (token) {
        case Token::kLeftParen:
        case Token::kRightParen:
        case Token::kLeftBrace:
        case Token::kRightBrace:
        case Token::kLeftBracket:
        case Token::kRightBracket:
        case Token::kColon:
        case Token::kSemicolon:
        case Token::kComma:
        case Token::kBitNot:
        case Token::kIllegal:
          // One character tokens.
          return Select(token);

        case Token::kConditional:
          // ? ?. ?? ??=
          Advance();
          if (c0_ == '.') {
            Advance();
            if (!IsDecimalDigit(c0_)) return Token::kQuestionPeriod;
            PushBack('.');
          } else if (c0_ == '?') {
            return Select('=', Token::kAssignNullish, Token::kNullish);
          }
          return Token::kConditional;

        case Token::kString:
          return ScanString();

        case Token::kLessThan:
          // < <= << <<= <!--
          Advance();
          if (c0_ == '=') return Select(Token::kLessThanEq);
          if (c0_ == '<') return Select('=', Token::kAssignShl, Token::kShl);
          if (c0_ == '!') {
            token = ScanHtmlComment();
            continue;
          }
          return Token::kLessThan;

        case Token::kGreaterThan:
          // > >= >> >>= >>> >>>=
          Advance();
          if (c0_ == '=') return Select(Token::kGreaterThanEq);
          if (c0_ == '>') {
            // >> >>= >>> >>>=
            Advance();
            if (c0_ == '=') return Select(Token::kAssignSar);
            if (c0_ == '>') return Select('=', Token::kAssignShr, Token::kShr);
            return Token::kSar;
          }
          return Token::kGreaterThan;

        case Token::kAssign:
          // = == === =>
          Advance();
          if (c0_ == '=') return Select('=', Token::kEqStrict, Token::kEq);
          if (c0_ == '>') return Select(Token::kArrow);
          return Token::kAssign;

        case Token::kNot:
          // ! != !==
          Advance();
          if (c0_ == '=')
            return Select('=', Token::kNotEqStrict, Token::kNotEq);
          return Token::kNot;

        case Token::kAdd:
          // + ++ +=
          Advance();
          if (c0_ == '+') return Select(Token::kInc);
          if (c0_ == '=') return Select(Token::kAssignAdd);
          return Token::kAdd;

        case Token::kSub:
          // - -- --> -=
          Advance();
          if (c0_ == '-') {
            Advance();
            if (c0_ == '>' && next().after_line_terminator) {
              // For compatibility with SpiderMonkey, we skip lines that
              // start with an HTML comment end '-->'.
              token = SkipSingleHTMLComment();
              continue;
            }
            return Token::kDec;
          }
          if (c0_ == '=') return Select(Token::kAssignSub);
          return Token::kSub;

        case Token::kMul:
          // * *=
          Advance();
          if (c0_ == '*') return Select('=', Token::kAssignExp, Token::kExp);
          if (c0_ == '=') return Select(Token::kAssignMul);
          return Token::kMul;

        case Token::kMod:
          // % %=
          return Select('=', Token::kAssignMod, Token::kMod);

        case Token::kDiv:
          // /  // /* /=
          Advance();
          if (c0_ == '/') {
            base::uc32 c = Peek();
            if (c == '#' || c == '@') {
              Advance();
              Advance();
              token = SkipMagicComment(c);
              continue;
            }
            token = SkipSingleLineComment();
            continue;
          }
          if (c0_ == '*') {
            token = SkipMultiLineComment();
            continue;
          }
          if (c0_ == '=') return Select(Token::kAssignDiv);
          return Token::kDiv;

        case Token::kBitAnd:
          // & && &= &&=
          Advance();
          if (c0_ == '&') return Select('=', Token::kAssignAnd, Token::kAnd);
          if (c0_ == '=') return Select(Token::kAssignBitAnd);
          return Token::kBitAnd;

        case Token::kBitOr:
          // | || |= ||=
          Advance();
          if (c0_ == '|') return Select('=', Token::kAssignOr, Token::kOr);
          if (c0_ == '=') return Select(Token::kAssignBitOr);
          return Token::kBitOr;

        case Token::kBitXor:
          // ^ ^=
          return Select('=', Token::kAssignBitXor, Token::kBitXor);

        case Token::kPeriod:
          // . Number
          Advance();
          if (IsDecimalDigit(c0_)) return ScanNumber(true);
          if (c0_ == '.') {
            if (Peek() == '.') {
              Advance();
              Advance();
              return Token::kEllipsis;
            }
          }
          return Token::kPeriod;

        case Token::kTemplateSpan:
          Advance();
          return ScanTemplateSpan();

        case Token::kPrivateName:
          if (source_pos() == 0 && Peek() == '!') {
            token = SkipSingleLineComment();
            continue;
          }
          return ScanPrivateName();

        case Token::kWhitespace:
          token = SkipWhiteSpace();
          continue;

        case Token::kNumber:
          return ScanNumber(false);

        case Token::kIdentifier:
          return ScanIdentifierOrKeyword();

        default:
          UNREACHABLE();
      }
    }

    if (IsIdentifierStart(c0_) ||
        (CombineSurrogatePair() && IsIdentifierStart(c0_))) {
      return ScanIdentifierOrKeyword();
    }
    if (c0_ == kEndOfInput) {
      return source_->has_parser_error() ? Token::kIllegal : Token::kEos;
    }
    token = SkipWhiteSpace();

    // Continue scanning for tokens as long as we're just skipping whitespace.
  } while (token == Token::kWhitespace);

  return token;
}

void Scanner::Scan(TokenDesc* next_desc) {
  DCHECK_EQ(next_desc, &next());

  next_desc->token = ScanSingleToken();
  DCHECK_IMPLIES(has_parser_error(), next_desc->token == Token::kIllegal);
  next_desc->location.end_pos = source_pos();

#ifdef DEBUG
  SanityCheckTokenDesc(current());
  SanityCheckTokenDesc(next());
  SanityCheckTokenDesc(next_next());
  SanityCheckTokenDesc(next_next_next());
#endif
}

void Scanner::Scan() { Scan(next_); }

}  // namespace internal
}  // namespace v8

#endif  // V8_PARSING_SCANNER_INL_H_
```