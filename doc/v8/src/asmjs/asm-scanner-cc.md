Response:
Let's break down the thought process for analyzing the `asm-scanner.cc` code.

1. **Understand the Core Problem:** The filename `asm-scanner.cc` immediately suggests its primary function: scanning. In the context of compilers and interpreters, a scanner (or lexer) takes raw input text and breaks it down into meaningful units called tokens. The `asmjs` part tells us it's specifically for the asm.js subset of JavaScript.

2. **Examine the Constructor (`AsmJsScanner::AsmJsScanner`):** The constructor reveals key data structures and initializations.
    * `Utf16CharacterStream* stream_`: This confirms the scanner operates on a stream of characters, which is expected. The `Utf16` suggests it handles Unicode.
    * `token_`, `preceding_token_`, `next_token_`: These variables strongly indicate the scanner's role in looking at the current, previous, and potentially next tokens. This is common in scanners to handle lookahead.
    * `position_`, `preceding_position_`, `next_position_`:  These track the position of the tokens in the input stream, crucial for error reporting and potentially source mapping.
    * `rewind_`: This flag suggests the scanner has the ability to go back, which is sometimes needed for parsing.
    * `in_local_scope_`: This hints at how the scanner handles identifiers within different scopes, a crucial aspect of any language.
    * `global_count_`: This variable suggests tracking the number of global identifiers encountered.
    * `double_value_`, `unsigned_value_`: These indicate the scanner's ability to parse numeric literals and store their values.
    * `preceded_by_newline_`:  This flag suggests handling of newlines, potentially related to statement terminators (or lack thereof) in asm.js.
    * `property_names_`, `global_names_`, `local_names_`: These are likely hash maps (or similar data structures) used to store and quickly look up identifiers and their corresponding token types. The initialization lists like `STDLIB_MATH_FUNCTION_LIST`, `KEYWORD_NAME_LIST`, etc., give us concrete examples of what kind of tokens the scanner recognizes. This is a *very* important part of the analysis.

3. **Analyze the `Next()` Method (the Heart of the Scanner):** This method is the workhorse. The structure is a loop that reads characters from the input stream and attempts to form tokens.
    * **Whitespace Handling:**  Ignoring spaces, tabs, and carriage returns is standard scanner behavior.
    * **Newline Handling:** The `preceded_by_newline_` update reinforces its importance.
    * **End of Input:** Handling `kEndOfInputU` is essential.
    * **String Literals:** The `ConsumeString` call shows how string literals are processed (though in this specific case, it's limited to "use asm").
    * **Comments:** Handling `//` and `/* ... */` comments is standard practice.
    * **Operators:** The `ConsumeCompareOrShift` indicates handling of multi-character operators like `<=`, `>>`, etc.
    * **Single-Character Tokens:** The `SIMPLE_SINGLE_TOKEN_LIST` suggests direct mapping of characters to tokens for many common symbols.
    * **Identifiers:** The `ConsumeIdentifier` call is where words are recognized.
    * **Numbers:** The `ConsumeNumber` call is where numeric literals are parsed, including different bases (binary, octal, hexadecimal).
    * **Error Handling:** The `token_ = kParseError` assignment is the mechanism for reporting syntax errors.

4. **Investigate Helper Methods:**  Methods like `Rewind()`, `ResetLocals()`, `Seek()`, `ConsumeIdentifier()`, `ConsumeNumber()`, `ConsumeCComment()`, `ConsumeCPPComment()`, `ConsumeString()`, `ConsumeCompareOrShift()`, `IsIdentifierStart()`, `IsIdentifierPart()`, and `IsNumberStart()` provide further details about the scanning process. Understanding these helps clarify the logic within `Next()`. For example, `ConsumeNumber()`'s handling of different number formats (decimal, hex, octal, binary) and potential errors is noteworthy.

5. **Consider the Context (asm.js):**  Knowing that this scanner is for asm.js is crucial. It explains why the string handling in `ConsumeString` is so specific ("use asm"). It also informs the limitations and optimizations in the number parsing. Asm.js has a specific structure and doesn't require the full flexibility of JavaScript.

6. **Address the Prompt's Specific Questions:**

    * **Functionality:** Summarize the findings from the above steps.
    * **Torque:** Check the filename extension; `.cc` is C++, not Torque (`.tq`).
    * **JavaScript Relationship (and Examples):** Since asm.js is a *subset* of JavaScript, the scanner's purpose is to parse that subset. Provide JavaScript examples that would be valid asm.js and how the scanner would tokenize them.
    * **Code Logic Inference (Hypothetical Input/Output):**  Choose a simple asm.js snippet and manually trace how the scanner would tokenize it, illustrating the input and output.
    * **Common Programming Errors:** Think about the kinds of syntax errors a programmer might make when writing asm.js code that this scanner would catch (e.g., invalid number formats, incorrect "use asm" directive).

7. **Structure the Answer:** Organize the information logically with clear headings and explanations. Use bullet points for lists of functionalities and examples. Provide code examples in code blocks for better readability.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:** "This looks like a standard scanner."
* **Refinement:** "Yes, but it's *specifically* for asm.js, which explains the constraints (e.g., the limited string handling)."
* **Initial Thought:** "The `property_names_`, `global_names_`, `local_names_` are just for storing identifiers."
* **Refinement:** "They also seem to be used for assigning token IDs to these identifiers, which is how the scanner maps names to internal representations."
* **Initial Thought:** "The `ConsumeNumber` function seems complex."
* **Refinement:** "It needs to handle different numeric bases and potential errors during conversion, which explains the detailed logic."

By following this structured approach and constantly refining understanding, one can effectively analyze and explain the functionality of a complex piece of source code like `asm-scanner.cc`.
好的，让我们来分析一下 `v8/src/asmjs/asm-scanner.cc` 这个文件的功能。

**1. 主要功能：asm.js 词法分析（Lexical Analysis）**

`v8/src/asmjs/asm-scanner.cc` 文件实现了一个专门用于解析 asm.js 代码的词法分析器（也称为扫描器）。词法分析是编译器的第一个阶段，它的主要任务是将输入的源代码字符流分解成一个个有意义的单元，这些单元被称为“词法单元”（tokens）。

**具体功能点：**

* **读取输入流:**  `AsmJsScanner` 类接收一个 `Utf16CharacterStream` 对象作为输入，该对象负责提供要扫描的字符。
* **识别词法单元:**  扫描器会逐个读取字符，并根据预定义的规则识别出不同的词法单元，例如：
    * **关键字:** `function`, `var`, `return` 等 (通过 `global_names_` 初始化)。
    * **标识符:** 变量名、函数名等 (通过 `ConsumeIdentifier` 处理)。
    * **字面量:** 数字（整数、浮点数）、字符串（仅限 "use asm"）。
    * **运算符:** `+`, `-`, `*`, `/`, `=`, `<`, `>`, `==`, `!=` 等。
    * **标点符号:** `(`, `)`, `{`, `}`, `;`, `,` 等。
    * **标准库函数和类型:** 例如 `Math.sin`, `Int32Array` 等 (通过 `property_names_` 初始化)。
* **存储词法单元信息:**  扫描器会存储当前识别到的词法单元的类型 (`token_`)、值（例如数字的值 `double_value_` 或 `unsigned_value_`）、位置 (`position_`) 等信息。
* **处理空白字符和注释:**  扫描器会跳过空格、制表符、换行符等空白字符，并识别和忽略单行注释 (`//`) 和多行注释 (`/* ... */`)。
* **支持 "use asm" 指令:**  扫描器会专门识别 `"use asm"` 字符串，并将其作为一个特殊的词法单元 (`kToken_UseAsm`) 处理。
* **错误处理:**  如果遇到无法识别的字符序列，扫描器会将 `token_` 设置为 `kParseError`，表示解析错误。
* **支持回溯 (Rewind):**  `Rewind()` 方法允许扫描器回退到上一个词法单元，这在语法分析阶段有时是必要的。
* **跟踪换行:** `preceded_by_newline_` 用于跟踪是否遇到换行符，这可能与 asm.js 中可选的分号有关。

**2. 关于文件扩展名和 Torque**

如果 `v8/src/asmjs/asm-scanner.cc` 的文件扩展名是 `.tq`，那么它确实是 V8 的 Torque 源代码。Torque 是 V8 用于生成高效的运行时代码的领域特定语言。 然而，根据你提供的信息，该文件的扩展名是 `.cc`，这意味着它是 **C++ 源代码**。因此，它不是 Torque 代码。

**3. 与 JavaScript 的功能关系及示例**

`v8/src/asmjs/asm-scanner.cc` 是 V8 引擎解析和编译 asm.js 代码的关键组成部分。asm.js 是 JavaScript 的一个严格子集，旨在提供接近本地代码的性能。

**JavaScript 示例：**

假设有以下简单的 asm.js 代码片段：

```javascript
"use asm";
function add(x, y) {
  x = x | 0;  // 类型标注：x 是 32 位整数
  y = y | 0;  // 类型标注：y 是 32 位整数
  return (x + y) | 0; // 返回结果是 32 位整数
}
```

`AsmJsScanner` 会将这段代码分解成以下词法单元序列（简化表示）：

* `"use asm"`  ->  `kToken_UseAsm`
* `function`  ->  `kToken_function`
* `add`      ->  `kGlobalsStart + 某个ID` (作为全局标识符)
* `(`        ->  `(`
* `x`        ->  `kLocalsStart - 某个ID` (作为局部标识符)
* `,`        ->  `,`
* `y`        ->  `kLocalsStart - 另一个ID`
* `)`        ->  `)`
* `{`        ->  `{`
* `x`        ->  `kLocalsStart - 之前x的ID`
* `=`        ->  `=`
* `x`        ->  `kLocalsStart - 之前x的ID`
* `|`        ->  `|`
* `0`        ->  `kUnsigned` (值为 0)
* `;`        ->  `;`
* `y`        ->  `kLocalsStart - 之前y的ID`
* `=`        ->  `=`
* `y`        ->  `kLocalsStart - 之前y的ID`
* `|`        ->  `|`
* `0`        ->  `kUnsigned` (值为 0)
* `;`        ->  `;`
* `return`   ->  `kToken_return`
* `(`        ->  `(`
* `x`        ->  `kLocalsStart - 之前x的ID`
* `+`        ->  `+`
* `y`        ->  `kLocalsStart - 之前y的ID`
* `)`        ->  `)`
* `|`        ->  `|`
* `0`        ->  `kUnsigned` (值为 0)
* `;`        ->  `;`
* `}`        ->  `}`

**4. 代码逻辑推理 (假设输入与输出)**

**假设输入:**  `"use asm"; var count = 10;`

**词法分析过程:**

1. 扫描器首先遇到字符串 `"`，开始尝试匹配字符串。它会匹配 `"use asm"`，并检查结尾的 `"`。 识别出 `kToken_UseAsm`。
2. 遇到 `;`，识别为 `;`。
3. 遇到空白字符，跳过。
4. 遇到标识符 `var`，在 `global_names_` 中查找，识别为 `kToken_var`。
5. 遇到空白字符，跳过。
6. 遇到标识符 `count`，由于之前没有遇到过，且不在预定义的关键字或标准库中，所以会被添加为新的全局标识符，并分配一个 `kGlobalsStart` 范围内的 token ID，例如 `kGlobalsStart + 0`。
7. 遇到空白字符，跳过。
8. 遇到 `=`，识别为 `=`.
9. 遇到数字 `10`，识别为无符号整数 `kUnsigned`，其 `unsigned_value_` 为 10。
10. 遇到 `;`，识别为 `;`。

**输出 (Token 序列，简化表示):**

`kToken_UseAsm`, `;`, `kToken_var`, `kGlobalsStart + 0` (代表 "count"), `=`, `kUnsigned(10)`, `;`

**5. 涉及用户常见的编程错误**

asm.js 是 JavaScript 的严格子集，因此一些在普通 JavaScript 中允许的语法在 asm.js 中可能会导致解析错误。`AsmJsScanner` 会在词法分析阶段捕获一些这类错误。

**常见错误示例：**

* **拼写错误的 "use asm" 指令:**
   ```javascript
   "use asmm"; // 拼写错误
   ```
   `AsmJsScanner` 在 `ConsumeString` 中会检查字符串是否完全匹配 "use asm"，如果拼写错误，则会设置 `token_ = kParseError`。

* **使用不允许的字符串:**
   ```javascript
   "use asm";
   var message = "hello"; // asm.js 不支持除 "use asm" 以外的字符串字面量
   ```
   当扫描器在 `ConsumeIdentifier` 或尝试识别字面量时遇到 `"`，但后续内容不是 "use asm"，则会报错。

* **无效的数字格式:**
   ```javascript
   "use asm";
   var value = 0xg; // 十六进制数字 'g' 无效
   ```
   在 `ConsumeNumber` 中，如果数字包含无效字符，`StringToDouble` 等函数会返回 NaN，扫描器会检测到并设置 `token_ = kParseError`。

* **使用了 asm.js 不支持的语法或关键字:**
   ```javascript
   "use asm";
   let x = 5; // 'let' 不是 asm.js 的关键字
   ```
   扫描器在尝试识别标识符时，如果遇到不在 asm.js 允许的关键字列表中的词，将会将其识别为标识符，但在后续的语法分析阶段可能会报错。虽然词法分析器本身不负责完全的语法验证，但它会识别出 `let` 作为一个标识符，而不是关键字。

* **缺少 "use asm" 指令:**
   ```javascript
   function add(x, y) { /* ... */ } // 缺少 "use asm"
   ```
   虽然这不是词法错误，但如果文件开头没有 `"use asm"` 指令，V8 不会将其作为 asm.js 代码处理。词法分析器会正常解析，但后续的编译和优化流程会有所不同。

总之，`v8/src/asmjs/asm-scanner.cc` 扮演着将 asm.js 源代码转化为一系列易于处理的词法单元的关键角色，为后续的语法分析和代码生成阶段奠定了基础。它对 asm.js 的严格语法规则进行初步的检查和识别，帮助 V8 引擎高效地处理这种高性能 JavaScript 子集。

Prompt: 
```
这是目录为v8/src/asmjs/asm-scanner.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/asmjs/asm-scanner.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/asmjs/asm-scanner.h"

#include <cinttypes>

#include "src/base/iterator.h"
#include "src/flags/flags.h"
#include "src/numbers/conversions.h"
#include "src/parsing/scanner.h"
#include "src/strings/char-predicates-inl.h"

namespace v8 {
namespace internal {

namespace {
// Cap number of identifiers to ensure we can assign both global and
// local ones a token id in the range of an int32_t.
static const int kMaxIdentifierCount = 0xF000000;
}  // namespace

AsmJsScanner::AsmJsScanner(Utf16CharacterStream* stream)
    : stream_(stream),
      token_(kUninitialized),
      preceding_token_(kUninitialized),
      next_token_(kUninitialized),
      position_(0),
      preceding_position_(0),
      next_position_(0),
      rewind_(false),
      in_local_scope_(false),
      global_count_(0),
      double_value_(0.0),
      unsigned_value_(0),
      preceded_by_newline_(false) {
#define V(name, _junk1, _junk2, _junk3) property_names_[#name] = kToken_##name;
  STDLIB_MATH_FUNCTION_LIST(V)
  STDLIB_ARRAY_TYPE_LIST(V)
#undef V
#define V(name, _junk1) property_names_[#name] = kToken_##name;
  STDLIB_MATH_VALUE_LIST(V)
#undef V
#define V(name) property_names_[#name] = kToken_##name;
  STDLIB_OTHER_LIST(V)
#undef V
#define V(name) global_names_[#name] = kToken_##name;
  KEYWORD_NAME_LIST(V)
#undef V
  Next();
}

void AsmJsScanner::Next() {
  if (rewind_) {
    preceding_token_ = token_;
    preceding_position_ = position_;
    token_ = next_token_;
    position_ = next_position_;
    next_token_ = kUninitialized;
    next_position_ = 0;
    rewind_ = false;
    return;
  }

  if (token_ == kEndOfInput || token_ == kParseError) {
    return;
  }

#if DEBUG
  if (v8_flags.trace_asm_scanner) {
    if (Token() == kDouble) {
      PrintF("%lf ", AsDouble());
    } else if (Token() == kUnsigned) {
      PrintF("%" PRIu32 " ", AsUnsigned());
    } else {
      std::string name = Name(Token());
      PrintF("%s ", name.c_str());
    }
  }
#endif

  preceded_by_newline_ = false;
  preceding_token_ = token_;
  preceding_position_ = position_;

  for (;;) {
    position_ = stream_->pos();
    base::uc32 ch = stream_->Advance();
    switch (ch) {
      case ' ':
      case '\t':
      case '\r':
        // Ignore whitespace.
        break;

      case '\n':
        // Track when we've passed a newline for optional semicolon support,
        // but keep scanning.
        preceded_by_newline_ = true;
        break;

      case kEndOfInputU:
        token_ = kEndOfInput;
        return;

      case '\'':
      case '"':
        ConsumeString(ch);
        return;

      case '/':
        ch = stream_->Advance();
        if (ch == '/') {
          ConsumeCPPComment();
        } else if (ch == '*') {
          if (!ConsumeCComment()) {
            token_ = kParseError;
            return;
          }
        } else {
          stream_->Back();
          token_ = '/';
          return;
        }
        // Breaks out of switch, but loops again (i.e. the case when we parsed
        // a comment, but need to continue to look for the next token).
        break;

      case '<':
      case '>':
      case '=':
      case '!':
        ConsumeCompareOrShift(ch);
        return;

#define V(single_char_token) case single_char_token:
        SIMPLE_SINGLE_TOKEN_LIST(V)
#undef V
        // Use fixed token IDs for ASCII.
        token_ = ch;
        return;

      default:
        if (IsIdentifierStart(ch)) {
          ConsumeIdentifier(ch);
        } else if (IsNumberStart(ch)) {
          ConsumeNumber(ch);
        } else {
          // TODO(bradnelson): Support unicode (probably via UnicodeCache).
          token_ = kParseError;
        }
        return;
    }
  }
}

void AsmJsScanner::Rewind() {
  DCHECK_NE(kUninitialized, preceding_token_);
  // TODO(bradnelson): Currently rewinding needs to leave in place the
  // preceding newline state (in case a |0 ends a line).
  // This is weird and stateful, fix me.
  DCHECK(!rewind_);
  next_token_ = token_;
  next_position_ = position_;
  token_ = preceding_token_;
  position_ = preceding_position_;
  preceding_token_ = kUninitialized;
  preceding_position_ = 0;
  rewind_ = true;
  identifier_string_.clear();
}

void AsmJsScanner::ResetLocals() { local_names_.clear(); }

#if DEBUG
// Only used for debugging.
std::string AsmJsScanner::Name(token_t token) const {
  if (token >= 32 && token < 127) {
    return std::string(1, static_cast<char>(token));
  }
  for (auto& i : local_names_) {
    if (i.second == token) {
      return i.first;
    }
  }
  for (auto& i : global_names_) {
    if (i.second == token) {
      return i.first;
    }
  }
  for (auto& i : property_names_) {
    if (i.second == token) {
      return i.first;
    }
  }
  switch (token) {
#define V(rawname, name) \
  case kToken_##name:    \
    return rawname;
    LONG_SYMBOL_NAME_LIST(V)
#undef V
#define V(name, value, string_name) \
  case name:                        \
    return string_name;
    SPECIAL_TOKEN_LIST(V)
    default:
      break;
#undef V
  }
  UNREACHABLE();
}
#endif

void AsmJsScanner::Seek(size_t pos) {
  stream_->Seek(pos);
  preceding_token_ = kUninitialized;
  token_ = kUninitialized;
  next_token_ = kUninitialized;
  preceding_position_ = 0;
  position_ = 0;
  next_position_ = 0;
  rewind_ = false;
  Next();
}

void AsmJsScanner::ConsumeIdentifier(base::uc32 ch) {
  // Consume characters while still part of the identifier.
  identifier_string_.clear();
  while (IsIdentifierPart(ch)) {
    identifier_string_ += ch;
    ch = stream_->Advance();
  }
  // Go back one for next time.
  stream_->Back();

  // Decode what the identifier means.
  if (preceding_token_ == '.') {
    auto i = property_names_.find(identifier_string_);
    if (i != property_names_.end()) {
      token_ = i->second;
      return;
    }
  } else {
    {
      auto i = local_names_.find(identifier_string_);
      if (i != local_names_.end()) {
        token_ = i->second;
        return;
      }
    }
    if (!in_local_scope_) {
      auto i = global_names_.find(identifier_string_);
      if (i != global_names_.end()) {
        token_ = i->second;
        return;
      }
    }
  }
  if (preceding_token_ == '.') {
    CHECK_LT(global_count_, kMaxIdentifierCount);
    token_ = kGlobalsStart + global_count_++;
    property_names_[identifier_string_] = token_;
  } else if (in_local_scope_) {
    CHECK_LT(local_names_.size(), kMaxIdentifierCount);
    token_ = kLocalsStart - static_cast<token_t>(local_names_.size());
    local_names_[identifier_string_] = token_;
  } else {
    CHECK_LT(global_count_, kMaxIdentifierCount);
    token_ = kGlobalsStart + global_count_++;
    global_names_[identifier_string_] = token_;
  }
}

namespace {
bool IsValidImplicitOctal(std::string_view number) {
  DCHECK_EQ(number[0], '0');
  return std::all_of(number.begin() + 1, number.end(), IsOctalDigit);
}
}  // namespace

void AsmJsScanner::ConsumeNumber(base::uc32 ch) {
  std::string number;
  number.assign(1, ch);
  bool has_dot = ch == '.';
  bool has_prefix = false;
  for (;;) {
    ch = stream_->Advance();
    if ((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
        (ch >= 'A' && ch <= 'F') || ch == '.' || ch == 'b' || ch == 'o' ||
        ch == 'x' ||
        ((ch == '-' || ch == '+') && !has_prefix &&
         (number[number.size() - 1] == 'e' ||
          number[number.size() - 1] == 'E'))) {
      // TODO(bradnelson): Test weird cases ending in -.
      if (ch == '.') {
        has_dot = true;
      }
      if (ch == 'b' || ch == 'o' || ch == 'x') {
        has_prefix = true;
      }
      number.push_back(ch);
    } else {
      break;
    }
  }
  stream_->Back();
  // Special case the most common number.
  if (number.size() == 1 && number[0] == '0') {
    unsigned_value_ = 0;
    token_ = kUnsigned;
    return;
  }
  // Pick out dot.
  if (number.size() == 1 && number[0] == '.') {
    token_ = '.';
    return;
  }
  // Decode numbers, with seperate paths for prefixes and implicit octals.
  if (has_prefix && number[0] == '0') {
    // "0[xob]" by itself is a parse error.
    if (number.size() <= 2) {
      token_ = kParseError;
      return;
    }
    switch (number[1]) {
      case 'b':
        double_value_ = BinaryStringToDouble(
            base::Vector<const uint8_t>::cast(base::VectorOf(number)));
        break;
      case 'o':
        double_value_ = OctalStringToDouble(
            base::Vector<const uint8_t>::cast(base::VectorOf(number)));
        break;
      case 'x':
        double_value_ = HexStringToDouble(
            base::Vector<const uint8_t>::cast(base::VectorOf(number)));
        break;
      default:
        // If there is a prefix character, but it's not the second character,
        // then there's a parse error somewhere.
        token_ = kParseError;
        break;
    }
  } else if (number[0] == '0' && !has_prefix && IsValidImplicitOctal(number)) {
    double_value_ = ImplicitOctalStringToDouble(
        base::Vector<const uint8_t>::cast(base::VectorOf(number)));
  } else {
    double_value_ = StringToDouble(
        base::Vector<const uint8_t>::cast(base::VectorOf(number)),
        NO_CONVERSION_FLAG);
  }
  if (std::isnan(double_value_)) {
    // Check if string to number conversion didn't consume all the characters.
    // This happens if the character filter let through something invalid
    // like: 0123ef for example.
    // TODO(bradnelson): Check if this happens often enough to be a perf
    // problem.
    if (number[0] == '.') {
      for (size_t k = 1; k < number.size(); ++k) {
        stream_->Back();
      }
      token_ = '.';
      return;
    }
    // Anything else that doesn't parse is an error.
    token_ = kParseError;
    return;
  }
  if (has_dot || trunc(double_value_) != double_value_) {
    token_ = kDouble;
  } else {
    // Exceeding safe integer range is an error.
    if (double_value_ > static_cast<double>(kMaxUInt32)) {
      token_ = kParseError;
      return;
    }
    unsigned_value_ = static_cast<uint32_t>(double_value_);
    token_ = kUnsigned;
  }
}

bool AsmJsScanner::ConsumeCComment() {
  for (;;) {
    base::uc32 ch = stream_->Advance();
    while (ch == '*') {
      ch = stream_->Advance();
      if (ch == '/') {
        return true;
      }
    }
    if (ch == '\n') {
      preceded_by_newline_ = true;
    }
    if (ch == kEndOfInputU) {
      return false;
    }
  }
}

void AsmJsScanner::ConsumeCPPComment() {
  for (;;) {
    base::uc32 ch = stream_->Advance();
    if (ch == '\n') {
      preceded_by_newline_ = true;
      return;
    }
    if (ch == kEndOfInputU) {
      return;
    }
  }
}

void AsmJsScanner::ConsumeString(base::uc32 quote) {
  // Only string allowed is 'use asm' / "use asm".
  const char* expected = "use asm";
  for (; *expected != '\0'; ++expected) {
    if (stream_->Advance() != static_cast<base::uc32>(*expected)) {
      token_ = kParseError;
      return;
    }
  }
  if (stream_->Advance() != quote) {
    token_ = kParseError;
    return;
  }
  token_ = kToken_UseAsm;
}

void AsmJsScanner::ConsumeCompareOrShift(base::uc32 ch) {
  base::uc32 next_ch = stream_->Advance();
  if (next_ch == '=') {
    switch (ch) {
      case '<':
        token_ = kToken_LE;
        break;
      case '>':
        token_ = kToken_GE;
        break;
      case '=':
        token_ = kToken_EQ;
        break;
      case '!':
        token_ = kToken_NE;
        break;
      default:
        UNREACHABLE();
    }
  } else if (ch == '<' && next_ch == '<') {
    token_ = kToken_SHL;
  } else if (ch == '>' && next_ch == '>') {
    if (stream_->Advance() == '>') {
      token_ = kToken_SHR;
    } else {
      token_ = kToken_SAR;
      stream_->Back();
    }
  } else {
    stream_->Back();
    token_ = ch;
  }
}

bool AsmJsScanner::IsIdentifierStart(base::uc32 ch) {
  return base::IsInRange(AsciiAlphaToLower(ch), 'a', 'z') || ch == '_' ||
         ch == '$';
}

bool AsmJsScanner::IsIdentifierPart(base::uc32 ch) {
  return IsAsciiIdentifier(ch);
}

bool AsmJsScanner::IsNumberStart(base::uc32 ch) {
  return ch == '.' || IsDecimalDigit(ch);
}

}  // namespace internal
}  // namespace v8

"""

```