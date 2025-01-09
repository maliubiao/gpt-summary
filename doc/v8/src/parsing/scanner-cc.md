Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Understanding - The Basics:**

* **Language:** The code is clearly C++. The file extension `.cc` confirms this. The comments referencing "the V8 project" and "ECMA-262" immediately signal it's related to JavaScript execution.
* **Purpose:** The file name `scanner.cc` strongly suggests its role: scanning input text (likely JavaScript source code) and breaking it down into meaningful units (tokens). The inclusion of headers like `<stdint.h>`, `<cmath>`, `<optional>`, `"src/ast/ast-value-factory.h"`, `"src/parsing/parse-info.h"`, etc., reinforces this idea by indicating data types, utility functions, and connections to the abstract syntax tree (AST) construction process.

**2. Scanning for Core Functionality - Keyword Spotting:**

I'd start by scanning for keywords and common patterns associated with lexical analysis:

* **`Scanner` class:** This is the central entity. Its constructor, methods like `Scan`, `Next`, `PeekAhead`, `Skip...Comment`, `Scan...`, and the presence of `TokenDesc` strongly suggest tokenization.
* **`Token` enum/class:**  References to `Token::k...` values confirm the existence of a token type enumeration.
* **`Advance()`:** This function is a telltale sign of a character-by-character processing loop.
* **`LiteralBuffer`:**  Indicates the accumulation of characters to form token values (like identifiers or string literals).
* **Error handling:**  `ReportScannerError`, `MessageTemplate` suggest error reporting during the scanning process.
* **Comment handling:** `SkipSingleLineComment`, `SkipMultiLineComment`, `ScanHtmlComment`.
* **String and Number handling:** `ScanString`, `ScanNumber`, `ScanHexNumber`, `ScanOctalEscape`, etc.
* **Identifier/Keyword handling:** `ScanIdentifierOrKeywordInner`.
* **Template literals:** `ScanTemplateSpan`, `Token::kTemplateSpan`, `Token::kTemplateTail`.
* **Regular expressions:** `ScanRegExpPattern`, `ScanRegExpFlags`.

**3. Categorizing Functionality - Grouping Similar Actions:**

Based on the keywords and patterns, I'd group the functionalities:

* **Token Consumption & Movement:** `Next`, `PeekAhead`, `PeekAheadAhead`, `SeekForward`. These control the flow of tokens.
* **Comment Handling:** `SkipSingleLineComment`, `SkipMultiLineComment`, `ScanHtmlComment`, `SkipMagicComment`.
* **Literal Scanning:**  This is a major category.
    * **Strings:** `ScanString`, `ScanEscape`, `ScanUnicodeEscape`, `ScanHexNumber`, `ScanOctalEscape`.
    * **Numbers:** `ScanNumber`, `ScanDecimalDigits`, `ScanBinaryDigits`, `ScanOctalDigits`, `ScanHexDigits`, handling of numeric separators.
    * **Template Literals:** `ScanTemplateSpan`.
    * **Regular Expressions:** `ScanRegExpPattern`, `ScanRegExpFlags`.
    * **Identifiers/Keywords:** `ScanIdentifierOrKeywordInner`, `ScanPrivateName`.
* **Error Handling:**  `ReportScannerError`, `ErrorState`.
* **Source Information:** `SourceUrl`, `SourceMappingUrl`.
* **Bookmarks:** `BookmarkScope`. This is for backtracking or re-scanning.
* **Initialization:** `Initialize`.
* **Utilities:** `IsInvalid`.

**4. Addressing Specific Instructions:**

* **`.tq` extension:**  The code is `.cc`, so it's C++, not Torque.
* **Relationship to JavaScript:** The presence of features like template literals, regular expressions, and keywords directly maps to JavaScript syntax. The code's purpose – lexical analysis – is fundamental to parsing JavaScript.
* **JavaScript examples:** I'd choose simple examples illustrating the scanner's role, like tokenizing a string literal, a number, an identifier, and a comment.
* **Code logic/Assumptions:** For a simple example, I might choose the `ScanNumber` function and illustrate how it handles different number formats (decimal, hexadecimal, etc.) based on input.
* **Common programming errors:**  I'd think about common mistakes in JavaScript syntax that the scanner would catch, such as unterminated strings, invalid escape sequences, or incorrect number formats.
* **Overall Functionality (Summarization):**  Combine the categorized functionalities into a concise description of the scanner's role.

**5. Refinement and Structuring:**

Finally, I'd organize the information logically, using headings and bullet points for clarity. I'd ensure the language is precise and avoids jargon where possible. The goal is to provide a comprehensive yet understandable overview of the code's functionality.

**Self-Correction/Refinement during the Process:**

* **Initially, I might focus too much on the low-level details.** I would then step back and focus on the *purpose* of each section of code.
* **I might miss a key functionality initially.** A second pass through the code, focusing on different types of constructs (e.g., comments, literals, identifiers), would help catch these.
* **The connection to JavaScript might not be immediately obvious for all parts.**  Thinking about how each part of the code contributes to the overall process of understanding and executing JavaScript is crucial. For example, `BookmarkScope` might seem abstract, but it's related to parsing and error recovery in the JavaScript engine.

By following this structured thought process, I can effectively analyze the C++ code snippet and provide a comprehensive and accurate explanation of its functionality within the context of the V8 JavaScript engine.
这是对 V8 源代码文件 `v8/src/parsing/scanner.cc` 的分析。

**功能归纳：**

`v8/src/parsing/scanner.cc` 文件的核心功能是实现 **JavaScript 源代码的词法分析（Scanning 或 Lexing）**。它负责将输入的 JavaScript 源代码字符流分解成一系列有意义的 **词法单元（Tokens）**。这些 Tokens 是编译器或解释器进一步进行语法分析的基础。

**具体功能点：**

1. **读取和处理输入字符流:** `Scanner` 类接收一个 `Utf16CharacterStream` 对象作为输入，负责从源代码中逐个读取 Unicode 字符。
2. **识别和生成 Tokens:**  `Scanner` 的主要任务是识别不同的词法单元，例如：
    * **关键字 (Keywords):** `if`, `else`, `function`, `var` 等。
    * **标识符 (Identifiers):** 变量名、函数名等。
    * **字面量 (Literals):**
        * 数字 (Numbers): `123`, `3.14`, `0xFF`, `1e-3` 等。
        * 字符串 (Strings): `"hello"`, `'world'` 等。
        * 布尔值 (Booleans): `true`, `false`.
        * `null`.
    * **运算符 (Operators):** `+`, `-`, `*`, `/`, `=`, `==`, `!=` 等。
    * **分隔符 (Punctuators):** `(`, `)`, `{`, `}`, `;`, `,`, `.` 等。
    * **注释 (Comments):** `//` 单行注释, `/* */` 多行注释, `<!--` HTML 风格注释。
    * **模板字面量 (Template Literals):**  `` `hello ${name}` ``。
    * **正则表达式 (Regular Expressions):** `/pattern/flags`。
    * **私有名称 (Private Names):** `#privateField`。
3. **处理空白符和换行符:**  识别并处理空格、制表符、换行符等，并标记换行符的位置，这对于某些语法规则（如自动分号插入）很重要。
4. **错误处理:**  当遇到无法识别的字符序列或不符合语法规则的情况时，`Scanner` 会报告词法错误。
5. **支持 Unicode 转义:**  处理如 `\uXXXX` 和 `\u{XXXXX}` 形式的 Unicode 转义序列。
6. **支持十六进制和八进制转义:**  处理字符串和模板字面量中的 `\xNN` 和 `\0` 到 `\777` 形式的转义。
7. **处理数字字面量:**  识别不同进制的数字（十进制、十六进制、八进制、二进制），并处理数字分隔符 `_`。
8. **处理模板字面量:**  扫描模板字面量的内容，包括插值表达式 `${}`。
9. **处理正则表达式:**  扫描正则表达式的模式和标志。
10. **处理 HTML 风格注释:**  识别并跳过 HTML 风格的注释 `<!-- ... -->`。
11. **记录源代码位置信息:**  为每个 Token 记录其在源代码中的起始和结束位置，用于错误报告和调试。
12. **处理魔术注释 (Magic Comments):**  例如 `//# sourceURL=` 和 `//# sourceMappingURL=`, 用于指定源代码的 URL 和 Source Map URL。
13. **支持严格模式 (Strict Mode) 的错误检测:**  例如，禁止在严格模式下使用八进制字面量和 `\8`, `\9` 转义。
14. **支持 BigInt 字面量:**  识别以 `n` 结尾的 BigInt 字面量。
15. **使用 Bookmark 机制:**  允许在扫描过程中设置书签，并在需要时回溯到之前的状态，这通常用于处理语法歧义或尝试不同的解析路径。

**关于文件扩展名和 Torque：**

你提到的 `.tq` 文件扩展名是 V8 中用于 **Torque** 语言的。Torque 是一种用于编写 V8 内部运行时代码的领域特定语言。由于 `v8/src/parsing/scanner.cc` 的扩展名是 `.cc`，这意味着它是 **C++** 源代码，而不是 Torque 源代码。

**与 JavaScript 功能的关系及示例：**

`v8/src/parsing/scanner.cc` 的功能直接关系到所有 JavaScript 代码的执行。 任何 JavaScript 代码在被 V8 执行之前，都必须经过词法分析阶段。

**JavaScript 示例：**

```javascript
// 这是一个单行注释
/*
 * 这是一个
 * 多行注释
 */

let myVariable = 123.45;
const message = "Hello, world!";
const templateString = `The value is ${myVariable}`;
const regex = /abc/g;
const obj = { key: 'value' };

function myFunction(param1, param2) {
  if (param1 > param2) {
    return true;
  } else {
    return false;
  }
}
```

当 `scanner.cc` 处理这段代码时，它会生成如下的 Token 序列（简化）：

* `// 这是一个单行注释` -> `kWhitespace` (表示这是一个空白或注释)
* `/* ... */` -> `kWhitespace`
* `let` -> `kLet` (关键字)
* `myVariable` -> `kIdentifier` (标识符)
* `=` -> `kAssign` (赋值运算符)
* `123.45` -> `kNumber` (数字字面量)
* `;` -> `kSemicolon` (分号)
* `const` -> `kConst`
* `message` -> `kIdentifier`
* `=` -> `kAssign`
* `"Hello, world!"` -> `kString` (字符串字面量)
* `;` -> `kSemicolon`
* `const` -> `kConst`
* `templateString` -> `kIdentifier`
* `=` -> `kAssign`
* `` `The value is ` `` -> `kTemplateHead` (模板字面量的头部)
* `${` -> `kTemplateSubstitutionStart` (模板插值开始)
* `myVariable` -> `kIdentifier`
* `}` -> `kTemplateSubstitutionEnd` (模板插值结束)
* `` `}` `` -> `kTemplateTail` (模板字面量的尾部)
* ... 以及后续代码的 Token

**代码逻辑推理 (假设输入与输出)：**

**假设输入：** 字符串 `"  var count = 0xFF;  "`

**扫描过程和输出（简化）：**

1. **读取空格:**  扫描器读取开头的空格，生成 `kWhitespace` Token。
2. **识别关键字 "var":**  扫描器读取 "var"，匹配到关键字，生成 `kVar` Token，并记录其位置信息。
3. **读取空格:** 生成 `kWhitespace` Token。
4. **识别标识符 "count":** 扫描器读取 "count"，识别为标识符，生成 `kIdentifier` Token，并记录其字面量值为 "count"。
5. **读取空格:** 生成 `kWhitespace` Token。
6. **识别赋值运算符 "=":** 生成 `kAssign` Token.
7. **读取空格:** 生成 `kWhitespace` Token。
8. **识别十六进制数字 "0xFF":** 扫描器读取 "0"，然后 "x"，判断是十六进制数，继续读取 "FF"，生成 `kNumber` Token，并记录其字面量值为 "0xFF"，可能还会将其转换为数值 255。
9. **识别分号 ";":** 生成 `kSemicolon` Token。
10. **读取空格:** 生成 `kWhitespace` Token。

**假设输出的 Token 序列 (简化表示)：**

```
[
  { type: 'kWhitespace', value: '  ', start: 0, end: 2 },
  { type: 'kVar', value: 'var', start: 2, end: 5 },
  { type: 'kWhitespace', value: ' ', start: 5, end: 6 },
  { type: 'kIdentifier', value: 'count', start: 6, end: 11 },
  { type: 'kWhitespace', value: ' ', start: 11, end: 12 },
  { type: 'kAssign', value: '=', start: 12, end: 13 },
  { type: 'kWhitespace', value: ' ', start: 13, end: 14 },
  { type: 'kNumber', value: '0xFF', start: 14, end: 18 },
  { type: 'kSemicolon', value: ';', start: 18, end: 19 },
  { type: 'kWhitespace', value: '  ', start: 19, end: 21 }
]
```

**用户常见的编程错误及示例：**

1. **未终止的字符串:**
   ```javascript
   const str = "hello; // 错误：字符串没有引号结尾
   ```
   扫描器会在此处报错，因为它遇到了换行符但没有找到字符串的结束引号。

2. **非法的字符:**
   ```javascript
   let a = 1@; // 错误：@ 不是有效的标识符字符
   ```
   扫描器会报错，因为 `@` 在这里不是合法的 Token 组成部分。

3. **错误的数字格式:**
   ```javascript
   let num = 08; // 错误：在非严格模式下是八进制，但包含非八进制数字
   ```
   扫描器会根据模式和规则进行处理，可能在严格模式下报错，或者在非严格模式下将其解释为十进制数。

4. **模板字面量中缺少 `${}` 的闭合花括号:**
   ```javascript
   const name = "Alice";
   const greeting = `Hello, ${name`; // 错误：缺少 }
   ```
   扫描器会检测到模板字面量未正确闭合。

5. **正则表达式中缺少 `/` 分隔符:**
   ```javascript
   const pattern = abc/g; // 错误：缺少起始的 /
   ```
   扫描器无法识别 `abc/g` 为有效的正则表达式。

**归纳其功能 (第 1 部分)：**

`v8/src/parsing/scanner.cc` 的主要功能是作为 V8 引擎中 JavaScript 源代码的 **词法分析器 (Lexer)**。它负责读取源代码字符流，识别并生成构成 JavaScript 语法结构的 **词法单元 (Tokens)**。这个过程是 JavaScript 代码编译和执行的第一步，为后续的语法分析和语义分析提供了基础。它涉及到识别关键字、标识符、字面量、运算符、分隔符、注释等，并处理 Unicode 转义、数字格式、模板字面量和正则表达式等复杂情况。同时，它还负责错误检测，报告词法分析阶段遇到的不符合语法规则的情况。

Prompt: 
```
这是目录为v8/src/parsing/scanner.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/parsing/scanner.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Features shared by parsing and pre-parsing scanners.

#include "src/parsing/scanner.h"

#include <stdint.h>

#include <cmath>
#include <optional>

#include "src/ast/ast-value-factory.h"
#include "src/base/strings.h"
#include "src/numbers/conversions-inl.h"
#include "src/numbers/conversions.h"
#include "src/objects/bigint.h"
#include "src/parsing/parse-info.h"
#include "src/parsing/scanner-inl.h"
#include "src/zone/zone.h"

namespace v8::internal {

class Scanner::ErrorState {
 public:
  ErrorState(MessageTemplate* message_stack, Scanner::Location* location_stack)
      : message_stack_(message_stack),
        old_message_(*message_stack),
        location_stack_(location_stack),
        old_location_(*location_stack) {
    *message_stack_ = MessageTemplate::kNone;
    *location_stack_ = Location::invalid();
  }

  ~ErrorState() {
    *message_stack_ = old_message_;
    *location_stack_ = old_location_;
  }

  void MoveErrorTo(TokenDesc* dest) {
    if (*message_stack_ == MessageTemplate::kNone) {
      return;
    }
    if (dest->invalid_template_escape_message == MessageTemplate::kNone) {
      dest->invalid_template_escape_message = *message_stack_;
      dest->invalid_template_escape_location = *location_stack_;
    }
    *message_stack_ = MessageTemplate::kNone;
    *location_stack_ = Location::invalid();
  }

 private:
  MessageTemplate* const message_stack_;
  MessageTemplate const old_message_;
  Scanner::Location* const location_stack_;
  Scanner::Location const old_location_;
};

// ----------------------------------------------------------------------------
// Scanner::BookmarkScope

const size_t Scanner::BookmarkScope::kNoBookmark =
    std::numeric_limits<size_t>::max() - 1;
const size_t Scanner::BookmarkScope::kBookmarkWasApplied =
    std::numeric_limits<size_t>::max();

void Scanner::BookmarkScope::Set(size_t position) {
  DCHECK_EQ(bookmark_, kNoBookmark);
  bookmark_ = position;
}

void Scanner::BookmarkScope::Apply() {
  DCHECK(HasBeenSet());  // Caller hasn't called SetBookmark.
  if (had_parser_error_) {
    scanner_->set_parser_error();
  } else {
    scanner_->reset_parser_error_flag();
    scanner_->SeekNext(bookmark_);
  }
  bookmark_ = kBookmarkWasApplied;
}

bool Scanner::BookmarkScope::HasBeenSet() const {
  return bookmark_ != kNoBookmark && bookmark_ != kBookmarkWasApplied;
}

bool Scanner::BookmarkScope::HasBeenApplied() const {
  return bookmark_ == kBookmarkWasApplied;
}

// ----------------------------------------------------------------------------
// Scanner

Scanner::Scanner(Utf16CharacterStream* source, UnoptimizedCompileFlags flags)
    : flags_(flags),
      source_(source),
      found_html_comment_(false),
      octal_pos_(Location::invalid()),
      octal_message_(MessageTemplate::kNone) {
  DCHECK_NOT_NULL(source);
}

void Scanner::Initialize() {
  // Need to capture identifiers in order to recognize "get" and "set"
  // in object literals.
  Init();
  next().after_line_terminator = true;
  Scan();
}

// static
bool Scanner::IsInvalid(base::uc32 c) {
  DCHECK(c == Invalid() || base::IsInRange(c, 0u, String::kMaxCodePoint));
  return c == Scanner::Invalid();
}

template <bool capture_raw, bool unicode>
base::uc32 Scanner::ScanHexNumber(int expected_length) {
  DCHECK_LE(expected_length, 4);  // prevent overflow

  int begin = source_pos() - 2;
  base::uc32 x = 0;
  for (int i = 0; i < expected_length; i++) {
    int d = base::HexValue(c0_);
    if (d < 0) {
      ReportScannerError(Location(begin, begin + expected_length + 2),
                         unicode
                             ? MessageTemplate::kInvalidUnicodeEscapeSequence
                             : MessageTemplate::kInvalidHexEscapeSequence);
      return Invalid();
    }
    x = x * 16 + d;
    Advance<capture_raw>();
  }

  return x;
}

template <bool capture_raw>
base::uc32 Scanner::ScanUnlimitedLengthHexNumber(base::uc32 max_value,
                                                 int beg_pos) {
  base::uc32 x = 0;
  int d = base::HexValue(c0_);
  if (d < 0) return Invalid();

  while (d >= 0) {
    x = x * 16 + d;
    if (x > max_value) {
      ReportScannerError(Location(beg_pos, source_pos() + 1),
                         MessageTemplate::kUndefinedUnicodeCodePoint);
      return Invalid();
    }
    Advance<capture_raw>();
    d = base::HexValue(c0_);
  }

  return x;
}

Token::Value Scanner::Next() {
  // Rotate through tokens.
  TokenDesc* previous = current_;
  current_ = next_;
  // Either we already have the next token lined up, in which case next_next_
  // simply becomes next_. In that case we use current_ as new next_next_ and
  // clear its token to indicate that it wasn't scanned yet. Otherwise we use
  // current_ as next_ and scan into it, leaving next_next_ uninitialized.
  if (V8_LIKELY(next_next().token == Token::kUninitialized)) {
    DCHECK(next_next_next().token == Token::kUninitialized);
    next_ = previous;
    // User 'previous' instead of 'next_' because for some reason the compiler
    // thinks 'next_' could be modified before the entry into Scan.
    previous->after_line_terminator = false;
    Scan(previous);
  } else {
    next_ = next_next_;

    if (V8_LIKELY(next_next_next().token == Token::kUninitialized)) {
      next_next_ = previous;
    } else {
      next_next_ = next_next_next_;
      next_next_next_ = previous;
    }

    previous->token = Token::kUninitialized;
    DCHECK_NE(Token::kUninitialized, current().token);
  }
  return current().token;
}

Token::Value Scanner::PeekAhead() {
  DCHECK(next().token != Token::kDiv);
  DCHECK(next().token != Token::kAssignDiv);

  if (next_next().token != Token::kUninitialized) {
    return next_next().token;
  }
  TokenDesc* temp = next_;
  next_ = next_next_;
  next().after_line_terminator = false;
  Scan();
  next_next_ = next_;
  next_ = temp;
  return next_next().token;
}

Token::Value Scanner::PeekAheadAhead() {
  if (next_next_next().token != Token::kUninitialized) {
    return next_next_next().token;
  }
  // PeekAhead() must be called first in order to call PeekAheadAhead().
  DCHECK(next_next().token != Token::kUninitialized);
  TokenDesc* temp = next_;
  TokenDesc* temp_next = next_next_;
  next_ = next_next_next_;
  next().after_line_terminator = false;
  Scan();
  next_next_next_ = next_;
  next_next_ = temp_next;
  next_ = temp;
  return next_next_next().token;
}

Token::Value Scanner::SkipSingleHTMLComment() {
  if (flags_.is_module()) {
    ReportScannerError(source_pos(), MessageTemplate::kHtmlCommentInModule);
    return Token::kIllegal;
  }
  return SkipSingleLineComment();
}

Token::Value Scanner::SkipSingleLineComment() {
  // The line terminator at the end of the line is not considered
  // to be part of the single-line comment; it is recognized
  // separately by the lexical grammar and becomes part of the
  // stream of input elements for the syntactic grammar (see
  // ECMA-262, section 7.4).
  AdvanceUntil([](base::uc32 c0) { return unibrow::IsLineTerminator(c0); });

  return Token::kWhitespace;
}

Token::Value Scanner::SkipMagicComment(base::uc32 hash_or_at_sign) {
  TryToParseMagicComment(hash_or_at_sign);
  if (unibrow::IsLineTerminator(c0_) || c0_ == kEndOfInput) {
    return Token::kWhitespace;
  }
  return SkipSingleLineComment();
}

void Scanner::TryToParseMagicComment(base::uc32 hash_or_at_sign) {
  // Magic comments are of the form: //[#@]\s<name>=\s*<value>\s*.* and this
  // function will just return if it cannot parse a magic comment.
  DCHECK(!IsWhiteSpaceOrLineTerminator(kEndOfInput));
  if (!IsWhiteSpace(c0_)) return;
  Advance();
  LiteralBuffer name;
  name.Start();

  while (c0_ != kEndOfInput && !IsWhiteSpaceOrLineTerminator(c0_) &&
         c0_ != '=') {
    name.AddChar(c0_);
    Advance();
  }
  if (!name.is_one_byte()) return;
  base::Vector<const uint8_t> name_literal = name.one_byte_literal();
  LiteralBuffer* value;
  LiteralBuffer compile_hints_value;
  if (name_literal == base::StaticOneByteVector("sourceURL")) {
    value = &source_url_;
  } else if (name_literal == base::StaticOneByteVector("sourceMappingURL")) {
    value = &source_mapping_url_;
    DCHECK(hash_or_at_sign == '#' || hash_or_at_sign == '@');
    saw_source_mapping_url_magic_comment_at_sign_ = hash_or_at_sign == '@';
  } else if (name_literal == base::StaticOneByteVector("eagerCompilation")) {
    value = &compile_hints_value;
  } else {
    return;
  }
  if (c0_ != '=')
    return;
  value->Start();
  Advance();
  while (IsWhiteSpace(c0_)) {
    Advance();
  }
  while (c0_ != kEndOfInput && !unibrow::IsLineTerminator(c0_)) {
    if (IsWhiteSpace(c0_)) {
      break;
    }
    value->AddChar(c0_);
    Advance();
  }
  // Allow whitespace at the end.
  while (c0_ != kEndOfInput && !unibrow::IsLineTerminator(c0_)) {
    if (!IsWhiteSpace(c0_)) {
      value->Start();
      break;
    }
    Advance();
  }
  if (value == &compile_hints_value && compile_hints_value.is_one_byte()) {
    base::Vector<const uint8_t> value_literal =
        compile_hints_value.one_byte_literal();
    if (value_literal == base::StaticOneByteVector("all")) {
      saw_magic_comment_compile_hints_all_ = true;
    }
  }
}

Token::Value Scanner::SkipMultiLineComment() {
  DCHECK_EQ(c0_, '*');

  // Until we see the first newline, check for * and newline characters.
  if (!next().after_line_terminator) {
    do {
      AdvanceUntil([](base::uc32 c0) {
        if (V8_UNLIKELY(static_cast<uint32_t>(c0) > kMaxAscii)) {
          return unibrow::IsLineTerminator(c0);
        }
        uint8_t char_flags = character_scan_flags[c0];
        return MultilineCommentCharacterNeedsSlowPath(char_flags);
      });

      while (c0_ == '*') {
        Advance();
        if (c0_ == '/') {
          Advance();
          return Token::kWhitespace;
        }
      }

      if (unibrow::IsLineTerminator(c0_)) {
        next().after_line_terminator = true;
        break;
      }
    } while (c0_ != kEndOfInput);
  }

  // After we've seen newline, simply try to find '*/'.
  while (c0_ != kEndOfInput) {
    AdvanceUntil([](base::uc32 c0) { return c0 == '*'; });

    while (c0_ == '*') {
      Advance();
      if (c0_ == '/') {
        Advance();
        return Token::kWhitespace;
      }
    }
  }

  return Token::kIllegal;
}

Token::Value Scanner::ScanHtmlComment() {
  // Check for <!-- comments.
  DCHECK_EQ(c0_, '!');
  Advance();
  if (c0_ != '-' || Peek() != '-') {
    PushBack('!');  // undo Advance()
    return Token::kLessThan;
  }
  Advance();

  found_html_comment_ = true;
  return SkipSingleHTMLComment();
}

#ifdef DEBUG
void Scanner::SanityCheckTokenDesc(const TokenDesc& token) const {
  // Only TEMPLATE_* tokens can have an invalid_template_escape_message.
  // kIllegal and kUninitialized can have garbage for the field.

  switch (token.token) {
    case Token::kUninitialized:
    case Token::kIllegal:
      // token.literal_chars & other members might be garbage. That's ok.
    case Token::kTemplateSpan:
    case Token::kTemplateTail:
      break;
    default:
      DCHECK_EQ(token.invalid_template_escape_message, MessageTemplate::kNone);
      break;
  }
}
#endif  // DEBUG

void Scanner::SeekForward(int pos) {
  // After this call, we will have the token at the given position as
  // the "next" token. The "current" token will be invalid.
  if (pos == next().location.beg_pos) return;
  int current_pos = source_pos();
  DCHECK_EQ(next().location.end_pos, current_pos);
  // Positions inside the lookahead token aren't supported.
  DCHECK(pos >= current_pos);
  if (pos != current_pos) {
    source_->Seek(pos);
    Advance();
    // This function is only called to seek to the location
    // of the end of a function (at the "}" token). It doesn't matter
    // whether there was a line terminator in the part we skip.
    next().after_line_terminator = false;
  }
  Scan();
}

template <bool capture_raw>
bool Scanner::ScanEscape() {
  base::uc32 c = c0_;
  Advance<capture_raw>();

  // Skip escaped newlines.
  DCHECK(!unibrow::IsLineTerminator(kEndOfInput));
  if (!capture_raw && unibrow::IsLineTerminator(c)) {
    // Allow escaped CR+LF newlines in multiline string literals.
    if (IsCarriageReturn(c) && IsLineFeed(c0_)) Advance();
    return true;
  }

  switch (c) {
    case 'b' : c = '\b'; break;
    case 'f' : c = '\f'; break;
    case 'n' : c = '\n'; break;
    case 'r' : c = '\r'; break;
    case 't' : c = '\t'; break;
    case 'u' : {
      c = ScanUnicodeEscape<capture_raw>();
      if (IsInvalid(c)) return false;
      break;
    }
    case 'v':
      c = '\v';
      break;
    case 'x': {
      c = ScanHexNumber<capture_raw>(2);
      if (IsInvalid(c)) return false;
      break;
    }
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
      c = ScanOctalEscape<capture_raw>(c, 2);
      break;
    case '8':
    case '9':
      // '\8' and '\9' are disallowed in strict mode.
      // Re-use the octal error state to propagate the error.
      octal_pos_ = Location(source_pos() - 2, source_pos() - 1);
      octal_message_ = capture_raw ? MessageTemplate::kTemplate8Or9Escape
                                   : MessageTemplate::kStrict8Or9Escape;
      break;
  }

  // Other escaped characters are interpreted as their non-escaped version.
  AddLiteralChar(c);
  return true;
}

template <bool capture_raw>
base::uc32 Scanner::ScanOctalEscape(base::uc32 c, int length) {
  DCHECK('0' <= c && c <= '7');
  base::uc32 x = c - '0';
  int i = 0;
  for (; i < length; i++) {
    int d = c0_ - '0';
    if (d < 0 || d > 7) break;
    int nx = x * 8 + d;
    if (nx >= 256) break;
    x = nx;
    Advance<capture_raw>();
  }
  // Anything except '\0' is an octal escape sequence, illegal in strict mode.
  // Remember the position of octal escape sequences so that an error
  // can be reported later (in strict mode).
  // We don't report the error immediately, because the octal escape can
  // occur before the "use strict" directive.
  if (c != '0' || i > 0 || IsNonOctalDecimalDigit(c0_)) {
    octal_pos_ = Location(source_pos() - i - 1, source_pos() - 1);
    octal_message_ = capture_raw ? MessageTemplate::kTemplateOctalLiteral
                                 : MessageTemplate::kStrictOctalEscape;
  }
  return x;
}

Token::Value Scanner::ScanString() {
  base::uc32 quote = c0_;

  next().literal_chars.Start();
  while (true) {
    AdvanceUntil([this](base::uc32 c0) {
      if (V8_UNLIKELY(static_cast<uint32_t>(c0) > kMaxAscii)) {
        if (V8_UNLIKELY(unibrow::IsStringLiteralLineTerminator(c0))) {
          return true;
        }
        AddLiteralChar(c0);
        return false;
      }
      uint8_t char_flags = character_scan_flags[c0];
      if (MayTerminateString(char_flags)) return true;
      AddLiteralChar(c0);
      return false;
    });

    while (c0_ == '\\') {
      Advance();
      // TODO(verwaest): Check whether we can remove the additional check.
      if (V8_UNLIKELY(c0_ == kEndOfInput || !ScanEscape<false>())) {
        return Token::kIllegal;
      }
    }

    if (c0_ == quote) {
      Advance();
      return Token::kString;
    }

    if (V8_UNLIKELY(c0_ == kEndOfInput ||
                    unibrow::IsStringLiteralLineTerminator(c0_))) {
      return Token::kIllegal;
    }

    AddLiteralChar(c0_);
  }
}

Token::Value Scanner::ScanPrivateName() {
  next().literal_chars.Start();
  DCHECK_EQ(c0_, '#');
  DCHECK(!IsIdentifierStart(kEndOfInput));
  int pos = source_pos();
  Advance();
  if (IsIdentifierStart(c0_) ||
      (CombineSurrogatePair() && IsIdentifierStart(c0_))) {
    AddLiteralChar('#');
    Token::Value token = ScanIdentifierOrKeywordInner();
    return token == Token::kIllegal ? Token::kIllegal : Token::kPrivateName;
  }

  ReportScannerError(pos, MessageTemplate::kInvalidOrUnexpectedToken);
  return Token::kIllegal;
}

Token::Value Scanner::ScanTemplateSpan() {
  // When scanning a TemplateSpan, we are looking for the following construct:
  // kTemplateSpan ::
  //     ` LiteralChars* ${
  //   | } LiteralChars* ${
  //
  // kTemplateTail ::
  //     ` LiteralChars* `
  //   | } LiteralChar* `
  //
  // A kTemplateSpan should always be followed by an Expression, while a
  // kTemplateTail terminates a TemplateLiteral and does not need to be
  // followed by an Expression.

  // These scoped helpers save and restore the original error state, so that we
  // can specially treat invalid escape sequences in templates (which are
  // handled by the parser).
  ErrorState scanner_error_state(&scanner_error_, &scanner_error_location_);
  ErrorState octal_error_state(&octal_message_, &octal_pos_);

  Token::Value result = Token::kTemplateSpan;
  next().literal_chars.Start();
  next().raw_literal_chars.Start();
  const bool capture_raw = true;
  while (true) {
    base::uc32 c = c0_;
    if (c == '`') {
      Advance();  // Consume '`'
      result = Token::kTemplateTail;
      break;
    } else if (c == '$' && Peek() == '{') {
      Advance();  // Consume '$'
      Advance();  // Consume '{'
      break;
    } else if (c == '\\') {
      Advance();  // Consume '\\'
      DCHECK(!unibrow::IsLineTerminator(kEndOfInput));
      if (capture_raw) AddRawLiteralChar('\\');
      if (unibrow::IsLineTerminator(c0_)) {
        // The TV of LineContinuation :: \ LineTerminatorSequence is the empty
        // code unit sequence.
        base::uc32 lastChar = c0_;
        Advance();
        if (lastChar == '\r') {
          // Also skip \n.
          if (c0_ == '\n') Advance();
          lastChar = '\n';
        }
        if (capture_raw) AddRawLiteralChar(lastChar);
      } else {
        bool success = ScanEscape<capture_raw>();
        USE(success);
        DCHECK_EQ(!success, has_error());
        // For templates, invalid escape sequence checking is handled in the
        // parser.
        scanner_error_state.MoveErrorTo(next_);
        octal_error_state.MoveErrorTo(next_);
      }
    } else if (c == kEndOfInput) {
      // Unterminated template literal
      break;
    } else {
      Advance();  // Consume c.
      // The TRV of LineTerminatorSequence :: <CR> is the CV 0x000A.
      // The TRV of LineTerminatorSequence :: <CR><LF> is the sequence
      // consisting of the CV 0x000A.
      if (c == '\r') {
        if (c0_ == '\n') Advance();  // Consume '\n'
        c = '\n';
      }
      if (capture_raw) AddRawLiteralChar(c);
      AddLiteralChar(c);
    }
  }
  next().location.end_pos = source_pos();
  next().token = result;

  return result;
}

template <typename IsolateT>
Handle<String> Scanner::SourceUrl(IsolateT* isolate) const {
  Handle<String> tmp;
  if (source_url_.length() > 0) {
    tmp = source_url_.Internalize(isolate);
  }
  return tmp;
}

template Handle<String> Scanner::SourceUrl(Isolate* isolate) const;
template Handle<String> Scanner::SourceUrl(LocalIsolate* isolate) const;

template <typename IsolateT>
Handle<String> Scanner::SourceMappingUrl(IsolateT* isolate) const {
  Handle<String> tmp;
  if (source_mapping_url_.length() > 0) {
    tmp = source_mapping_url_.Internalize(isolate);
  }
  return tmp;
}

template Handle<String> Scanner::SourceMappingUrl(Isolate* isolate) const;
template Handle<String> Scanner::SourceMappingUrl(LocalIsolate* isolate) const;

bool Scanner::ScanDigitsWithNumericSeparators(bool (*predicate)(base::uc32 ch),
                                              bool is_check_first_digit) {
  // we must have at least one digit after 'x'/'b'/'o'
  if (is_check_first_digit && !predicate(c0_)) return false;

  bool separator_seen = false;
  while (predicate(c0_) || c0_ == '_') {
    if (c0_ == '_') {
      Advance();
      if (c0_ == '_') {
        ReportScannerError(Location(source_pos(), source_pos() + 1),
                           MessageTemplate::kContinuousNumericSeparator);
        return false;
      }
      separator_seen = true;
      continue;
    }
    separator_seen = false;
    AddLiteralCharAdvance();
  }

  if (separator_seen) {
    ReportScannerError(Location(source_pos(), source_pos() + 1),
                       MessageTemplate::kTrailingNumericSeparator);
    return false;
  }

  return true;
}

bool Scanner::ScanDecimalDigits(bool allow_numeric_separator) {
  if (allow_numeric_separator) {
    return ScanDigitsWithNumericSeparators(&IsDecimalDigit, false);
  }
  while (IsDecimalDigit(c0_)) {
    AddLiteralCharAdvance();
  }
  if (c0_ == '_') {
    ReportScannerError(Location(source_pos(), source_pos() + 1),
                       MessageTemplate::kInvalidOrUnexpectedToken);
    return false;
  }
  return true;
}

bool Scanner::ScanDecimalAsSmiWithNumericSeparators(uint64_t* value) {
  bool separator_seen = false;
  while (IsDecimalDigit(c0_) || c0_ == '_') {
    if (c0_ == '_') {
      Advance();
      if (c0_ == '_') {
        ReportScannerError(Location(source_pos(), source_pos() + 1),
                           MessageTemplate::kContinuousNumericSeparator);
        return false;
      }
      separator_seen = true;
      continue;
    }
    separator_seen = false;
    *value = 10 * *value + (c0_ - '0');
    base::uc32 first_char = c0_;
    Advance();
    AddLiteralChar(first_char);
  }

  if (separator_seen) {
    ReportScannerError(Location(source_pos(), source_pos() + 1),
                       MessageTemplate::kTrailingNumericSeparator);
    return false;
  }

  return true;
}

bool Scanner::ScanDecimalAsSmi(uint64_t* value, bool allow_numeric_separator) {
  if (allow_numeric_separator) {
    return ScanDecimalAsSmiWithNumericSeparators(value);
  }

  while (IsDecimalDigit(c0_)) {
    *value = 10 * *value + (c0_ - '0');
    base::uc32 first_char = c0_;
    Advance();
    AddLiteralChar(first_char);
  }
  return true;
}

bool Scanner::ScanBinaryDigits() {
  return ScanDigitsWithNumericSeparators(&IsBinaryDigit, true);
}

bool Scanner::ScanOctalDigits() {
  return ScanDigitsWithNumericSeparators(&IsOctalDigit, true);
}

bool Scanner::ScanImplicitOctalDigits(int start_pos,
                                      Scanner::NumberKind* kind) {
  DCHECK_EQ(*kind, IMPLICIT_OCTAL);

  while (true) {
    // (possible) octal number
    if (IsNonOctalDecimalDigit(c0_)) {
      *kind = DECIMAL_WITH_LEADING_ZERO;
      return true;
    }
    if (!IsOctalDigit(c0_)) {
      // Octal literal finished.
      octal_pos_ = Location(start_pos, source_pos());
      octal_message_ = MessageTemplate::kStrictOctalLiteral;
      return true;
    }
    AddLiteralCharAdvance();
  }
}

bool Scanner::ScanHexDigits() {
  return ScanDigitsWithNumericSeparators(&IsHexDigit, true);
}

bool Scanner::ScanSignedInteger() {
  if (c0_ == '+' || c0_ == '-') AddLiteralCharAdvance();
  // we must have at least one decimal digit after 'e'/'E'
  if (!IsDecimalDigit(c0_)) return false;
  return ScanDecimalDigits(true);
}

Token::Value Scanner::ScanNumber(bool seen_period) {
  DCHECK(IsDecimalDigit(c0_));  // the first digit of the number or the fraction

  NumberKind kind = DECIMAL;

  next().literal_chars.Start();
  bool at_start = !seen_period;
  int start_pos = source_pos();  // For reporting octal positions.
  if (seen_period) {
    // we have already seen a decimal point of the float
    AddLiteralChar('.');
    if (c0_ == '_') {
      return Token::kIllegal;
    }
    // we know we have at least one digit
    if (!ScanDecimalDigits(true)) return Token::kIllegal;
  } else {
    // if the first character is '0' we must check for octals and hex
    if (c0_ == '0') {
      AddLiteralCharAdvance();

      // either 0, 0exxx, 0Exxx, 0.xxx, a hex number, a binary number or
      // an octal number.
      if (AsciiAlphaToLower(c0_) == 'x') {
        AddLiteralCharAdvance();
        kind = HEX;
        if (!ScanHexDigits()) return Token::kIllegal;
      } else if (AsciiAlphaToLower(c0_) == 'o') {
        AddLiteralCharAdvance();
        kind = OCTAL;
        if (!ScanOctalDigits()) return Token::kIllegal;
      } else if (AsciiAlphaToLower(c0_) == 'b') {
        AddLiteralCharAdvance();
        kind = BINARY;
        if (!ScanBinaryDigits()) return Token::kIllegal;
      } else if (IsOctalDigit(c0_)) {
        kind = IMPLICIT_OCTAL;
        if (!ScanImplicitOctalDigits(start_pos, &kind)) {
          return Token::kIllegal;
        }
        if (kind == DECIMAL_WITH_LEADING_ZERO) {
          at_start = false;
        }
      } else if (IsNonOctalDecimalDigit(c0_)) {
        kind = DECIMAL_WITH_LEADING_ZERO;
      } else if (c0_ == '_') {
        ReportScannerError(Location(source_pos(), source_pos() + 1),
                           MessageTemplate::kZeroDigitNumericSeparator);
        return Token::kIllegal;
      }
    }

    // Parse decimal digits and allow trailing fractional part.
    if (IsDecimalNumberKind(kind)) {
      bool allow_numeric_separator = kind != DECIMAL_WITH_LEADING_ZERO;
      // This is an optimization for parsing Decimal numbers as Smi's.
      if (at_start) {
        uint64_t value = 0;
        // scan subsequent decimal digits
        if (!ScanDecimalAsSmi(&value, allow_numeric_separator)) {
          return Token::kIllegal;
        }

        if (next().literal_chars.one_byte_literal().length() <= 10 &&
            value <= Smi::kMaxValue && c0_ != '.' && !IsIdentifierStart(c0_)) {
          next().smi_value = static_cast<uint32_t>(value);

          if (kind == DECIMAL_WITH_LEADING_ZERO) {
            octal_pos_ = Location(start_pos, source_pos());
            octal_message_ = MessageTemplate::kStrictDecimalWithLeadingZero;
          }
          return Token::kSmi;
        }
      }

      if (!ScanDecimalDigits(allow_numeric_separator)) {
        return Token::kIllegal;
      }
      if (c0_ == '.') {
        seen_period = true;
        AddLiteralCharAdvance();
        if (c0_ == '_') {
          return Token::kIllegal;
        }
        if (!ScanDecimalDigits(true)) return Token::kIllegal;
      }
    }
  }

  bool is_bigint = false;
  if (c0_ == 'n' && !seen_period && IsValidBigIntKind(kind)) {
    // Check that the literal is within our limits for BigInt length.
    // For simplicity, use 4 bits per character to calculate the maximum
    // allowed literal length.
    static const int kMaxBigIntCharacters = BigInt::kMaxLengthBits / 4;
    int length = source_pos() - start_pos - (kind != DECIMAL ? 2 : 0);
    if (length > kMaxBigIntCharacters) {
      ReportScannerError(Location(start_pos, source_pos()),
                         MessageTemplate::kBigIntTooBig);
      return Token::kIllegal;
    }

    is_bigint = true;
    Advance();
  } else if (AsciiAlphaToLower(c0_) == 'e') {
    // scan exponent, if any
    DCHECK_NE(kind, HEX);  // 'e'/'E' must be scanned as part of the hex number

    if (!IsDecimalNumberKind(kind)) return Token::kIllegal;

    // scan exponent
    AddLiteralCharAdvance();

    if (!ScanSignedInteger()) return Token::kIllegal;
  }

  // The source character immediately following a numeric literal must
  // not be an identifier start or a decimal digit; see ECMA-262
  // section 7.8.3, page 17 (note that we read only one decimal digit
  // if the value is 0).
  if (IsDecimalDigit(c0_) || IsIdentifierStart(c0_)) {
    return Token::kIllegal;
  }

  if (kind == DECIMAL_WITH_LEADING_ZERO) {
    octal_pos_ = Location(start_pos, source_pos());
    octal_message_ = MessageTemplate::kStrictDecimalWithLeadingZero;
  }

  next().number_kind = kind;
  return is_bigint ? Token::kBigInt : Token::kNumber;
}

base::uc32 Scanner::ScanIdentifierUnicodeEscape() {
  Advance();
  if (c0_ != 'u') return Invalid();
  Advance();
  return ScanUnicodeEscape<false>();
}

template <bool capture_raw>
base::uc32 Scanner::ScanUnicodeEscape() {
  // Accept both \uxxxx and \u{xxxxxx}. In the latter case, the number of
  // hex digits between { } is arbitrary. \ and u have already been read.
  if (c0_ == '{') {
    int begin = source_pos() - 2;
    Advance<capture_raw>();
    base::uc32 cp =
        ScanUnlimitedLengthHexNumber<capture_raw>(String::kMaxCodePoint, begin);
    if (cp == kInvalidSequence || c0_ != '}') {
      ReportScannerError(source_pos(),
                         MessageTemplate::kInvalidUnicodeEscapeSequence);
      return Invalid();
    }
    Advance<capture_raw>();
    return cp;
  }
  const bool unicode = true;
  return ScanHexNumber<capture_raw, unicode>(4);
}

Token::Value Scanner::ScanIdentifierOrKeywordInnerSlow(bool escaped,
                                                       bool can_be_keyword) {
  while (true) {
    if (c0_ == '\\') {
      escaped = true;
      base::uc32 c = ScanIdentifierUnicodeEscape();
      // Only allow legal identifier part characters.
      // TODO(verwaest): Make this true.
      // DCHECK(!IsIdentifierPart('\'));
      DCHECK(!IsIdentifierPart(Invalid()));
      if (c == '\\' || !IsIdentifierPart(c)) {
        return Token::kIllegal;
      }
      can_be_keyword = can_be_keyword && CharCanBeKeyword(c);
      AddLiteralChar(c);
    } else if (IsIdentifierPart(c0_) ||
               (CombineSurrogatePair() && IsIdentifierPart(c0_))) {
      can_be_keyword = can_be_keyword && CharCanBeKeyword(c0_);
      AddLiteralCharAdvance();
    } else {
      break;
    }
  }

  if (can_be_keyword && next().literal_chars.is_one_byte()) {
    base::Vector<const uint8_t> chars = next().literal_chars.one_byte_literal();
    Token::Value token =
        KeywordOrIdentifierToken(chars.begin(), chars.length());
    if (base::IsInRange(token, Token::kIdentifier, Token::kYield)) return token;

    if (token == Token::kFutureStrictReservedWord) {
      if (escaped) return Token::kEscapedStrictReservedWord;
      return token;
    }

    if (!escaped) return token;

    static_assert(Token::kLet + 1 == Token::kStatic);
    if (base::IsInRange(token, Token::kLet, Token::kStatic)) {
      return Token::kEscapedStrictReservedWord;
    }
    return Token::kEscapedKeyword;
  }

  return Token::kIdentifier;
}

bool Scanner::ScanRegExpPattern() {
  DCHECK_EQ(Token::kUninitialized, next_next().token);
  DCHECK(next().token == Token::kDiv || next().token == Token::kAssignDiv);

  // Scan: ('/' | '/=') RegularExpressionBody '/' RegularExpressionFlags
  bool in_character_class = false;

  // Scan regular expression body: According to ECMA-262, 3rd, 7.8.5,
  // the scanner should pass uninterpreted bodies to the RegExp
  // constructor.
  next().literal_chars.Start();
  if (next().token == Token::kAssignDiv) {
    AddLiteralChar('=');
  }

  while (c0_ != '/' || in_character_class) {
    if (c0_ == kEndOfInput || unibrow::IsLineTerminator(c0_)) {
      return false;
    }
    if (c0_ == '\\') {  // Escape sequence.
      AddLiteralCharAdvance();
      if (c0_ == kEndOfInput || unibrow::IsLineTerminator(c0_)) {
        return false;
      }
      AddLiteralCharAdvance();
      // If the escape allows more characters, i.e., \x??, \u????, or \c?,
      // only "safe" characters are allowed (letters, digits, underscore),
      // otherwise the escape isn't valid and the invalid character has
      // its normal meaning. I.e., we can just continue scanning without
      // worrying whether the following characters are part of the escape
      // or not, since any '/', '\\' or '[' is guaranteed to not be part
      // of the escape sequence.
    } else {  // Unescaped character.
      if (c0_ == '[') in_character_class = true;
      if (c0_ == ']') in_character_class = false;
      AddLiteralCharAdvance();
    }
  }
  Advance();  // consume '/'

  next().token = Token::kRegExpLiteral;
  return true;
}

std::optional<RegExpFlags> Scanner::ScanRegExpFlags() {
  DCHECK_EQ(Token::kRegExpLiteral, next().token);

  RegExpFlags flags;
  next().literal_chars.Start();
  while (IsIdentifierPart(c0_)) {
    std::optional<RegExpFlag> maybe_flag = JSRegExp::FlagFromChar(c0_);
    if (!maybe_flag.has_value()) return {};
    RegExpFlag flag = maybe_flag.value();
    if (flags & flag) return {};
    AddLiteralCharAdvance();
    flags |= flag;
  }

  next().location.end_pos = source_pos();
  return flags;
}

const AstRawString* Scanner::CurrentSymbol(
    AstValueFactory* ast_value_factory) const {
  if (is_literal_one_byte()) {
    return ast_value_factory->GetOneByteString(literal_one_byte_string());
  }
  return ast_value_factory->GetTwoByteString(literal_two_byte_string());
}

const AstRawString* Scanner::NextSymbol(
    AstValueFactory* ast_value_factory) const {
  if (is_next_literal_one_byte()) {
    return ast_value_factory->GetOneByteString(next_literal_one_byte_string());
  }
  return ast_value_factory->GetTwoByteString(next_literal_two_byte_string());
}

const AstRawString* Scanne
"""


```