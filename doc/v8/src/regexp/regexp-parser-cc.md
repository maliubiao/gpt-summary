Response:
My thinking process to summarize the provided C++ code snippet goes like this:

1. **Identify the Core Filename and Path:** The prompt explicitly states `v8/src/regexp/regexp-parser.cc`. This immediately tells me the code is related to parsing regular expressions within the V8 JavaScript engine.

2. **Scan for Key Data Structures:** I quickly look for class definitions and important data structures. The prominent ones I spot are:
    * `RegExpTextBuilder`:  This suggests building text components of the regex.
    * `RegExpBuilder`:  Seems like a higher-level builder, managing terms and alternatives.
    * `RegExpParserState`:  Likely manages the state during parsing, handling nested groups and captures.
    * `RegExpParserImpl`: This is the central parsing engine, templated for different character types.

3. **Infer Functionality from Class Names and Members:**  Based on the class names and their member functions, I start to deduce their roles:
    * `RegExpTextBuilder`: Functions like `AddCharacter`, `AddUnicodeCharacter`, `AddAtom`, `FlushText`, and `ToRegExp` indicate it's responsible for assembling sequences of characters or pre-built regex components (atoms) into `RegExpText` objects. The handling of surrogates points towards Unicode support.
    * `RegExpBuilder`:  Functions like `AddCharacter`, `AddAtom`, `AddTerm`, `AddAssertion`, `NewAlternative`, and `ToRegExp` suggest it orchestrates the building of the overall regex structure, handling alternatives (`|`) and quantifiers. It uses `RegExpTextBuilder` internally.
    * `RegExpParserState`:  Members like `previous_state_`, `builder_`, `group_type_`, and `capture_index_` clearly indicate it maintains the parsing context, especially for nested groups (capturing or non-capturing) and lookarounds.
    * `RegExpParserImpl`:  Functions like `ParsePattern`, `ParseDisjunction`, `ParseGroup`, `ParseCharacterClass`, and `ParseBackReferenceIndex` are strong indicators of the core parsing logic, breaking down the regex string into its components. The presence of `ParseHexEscape`, `ParseUnicodeEscape`, and `ParsePropertyClassName` highlights its handling of escape sequences and Unicode properties.

4. **Look for Control Flow and Key Parsing Concepts:** I search for patterns that reveal the parsing strategy. The nested `Parse...` functions (e.g., `ParsePattern` calling `ParseDisjunction`, which calls `ParseGroup`) suggest a recursive descent parser. The handling of quantifiers and alternatives is also evident.

5. **Identify Flags and Options:**  The code mentions `RegExpFlags` and functions like `IsIgnoreCase`, `IsMultiline`, `IsUnicode`, and `IsUnicodeSets`. This tells me the parser respects regex flags and handles different modes (case-insensitive, multiline, Unicode).

6. **Note Internationalization (ICU) Dependencies:** The `#ifdef V8_INTL_SUPPORT` blocks are significant. They show that the parser leverages the ICU library for more advanced Unicode features when it's available.

7. **Consider Potential Errors and Edge Cases:**  The `ReportError` function and checks for `kUnterminatedGroup` and `kUnmatchedParen` indicate error handling. The code dealing with surrogate pairs and Unicode desugaring points to handling complex Unicode scenarios.

8. **Synthesize a High-Level Summary:** Based on these observations, I start forming a concise summary of the file's purpose. The key aspects are: parsing regex strings, building an Abstract Syntax Tree (AST), handling different regex features (alternation, quantifiers, capturing groups, assertions), supporting Unicode and internationalization (if enabled), and managing parser state.

9. **Address Specific Prompt Questions:** I then go through the prompt's specific requests:
    * **Functionality:**  List the core functionalities identified in the previous steps.
    * **Torque:** Check if the filename ends in `.tq`. In this case, it's `.cc`, so it's not Torque.
    * **JavaScript Relation:** Explain that regex functionality is exposed in JavaScript through the `RegExp` object and its methods (`test`, `exec`, `match`, etc.). Provide a simple JavaScript example.
    * **Code Logic Inference:**  Select a small, understandable piece of logic (like `RegExpTextBuilder::AddCharacter`) and illustrate its behavior with a simple input and output example.
    * **Common Programming Errors:** Think about common regex mistakes that this parser would encounter, such as unterminated groups or invalid escape sequences.
    * **Overall Functionality (Summary):** Condense the high-level summary into a few key points.

10. **Refine and Organize:** Finally, I review the summary for clarity, accuracy, and completeness, organizing it logically based on the prompt's questions. I ensure the language is precise and avoids jargon where possible.
好的，让我们来分析一下 `v8/src/regexp/regexp-parser.cc` 这个文件的功能。

**功能归纳:**

`v8/src/regexp/regexp-parser.cc` 文件是 V8 JavaScript 引擎中负责解析正则表达式的核心组件。它的主要功能是将正则表达式字符串转换为 V8 内部使用的抽象语法树 (AST) 表示形式。这个 AST 随后会被用于正则表达式的编译和执行。

具体来说，这个文件包含了实现正则表达式语法分析器的代码，能够理解和解析各种正则表达式的语法结构，例如：

* **普通字符:**  例如 `a`, `b`, `c`, `1`, `2`, `3` 等。
* **特殊字符 (元字符):** 例如 `.`, `^`, `$`, `*`, `+`, `?`, `\`, `|`, `[]`, `()` 等，它们具有特殊的匹配意义。
* **字符类:** 例如 `[abc]`, `[^abc]`, `\d`, `\w`, `\s` 等，用于匹配一组字符。
* **量词:** 例如 `*`, `+`, `?`, `{n}`, `{n,}`, `{n,m}`，用于指定匹配字符出现的次数。
* **锚点:** 例如 `^` (匹配字符串的开头), `$` (匹配字符串的结尾), `\b` (匹配单词边界) 等。
* **分组和捕获:** 使用 `()` 进行分组，可以用于量词的作用域，也可以用于捕获匹配的子字符串。
* **非捕获分组:** 使用 `(?:...)` 创建非捕获分组。
* **反向引用:** 使用 `\1`, `\2` 等引用之前捕获的分组。
* **断言 (Lookaround):** 例如 `(?=...)` (正向前瞻), `(?!...)` (负向前瞻), `(?<=...)` (正向后顾 - ES2018), `(?<!...)` (负向后顾 - ES2018)。
* **Unicode 相关特性:**  支持 Unicode 字符，包括 Unicode 转义 (例如 `\u{...}`), Unicode 属性转义 (例如 `\p{...}`), 以及处理 Unicode 标志 (`u`) 和 Unicode Sets 标志 (`v`)。
* **命名捕获组:** 使用 `(?<name>...)` 创建具有名称的捕获组。
* **正则表达式标志:**  解析正则表达式的标志 (例如 `i` - 忽略大小写, `m` - 多行模式, `g` - 全局匹配, `u` - Unicode, `y` - 粘性匹配, `s` - dotAll, `v` - Unicode Sets)。

**关于文件类型和 JavaScript 关系:**

* **文件类型:**  由于 `v8/src/regexp/regexp-parser.cc` 以 `.cc` 结尾，这表明它是一个 C++ 源文件，而不是 v8 Torque 源文件 (`.tq`)。
* **JavaScript 关系:**  `v8/src/regexp/regexp-parser.cc` 与 JavaScript 的正则表达式功能有着直接且核心的联系。JavaScript 中的 `RegExp` 对象及其相关方法（如 `test()`, `exec()`, `match()`, `search()`, `replace()` 等）的底层实现依赖于这个解析器。

**JavaScript 举例说明:**

```javascript
// JavaScript 中使用正则表达式的例子

// 1. 创建一个正则表达式对象
const regex1 = /ab*c/;
const regex2 = new RegExp('ab*c');

// 2. 使用 test() 方法检查字符串是否匹配
const str1 = 'abbbc';
const str2 = 'defg';
console.log(regex1.test(str1)); // 输出: true
console.log(regex1.test(str2)); // 输出: false

// 3. 使用 exec() 方法执行匹配并返回匹配结果
const str3 = 'cdabbbcdef';
const result = regex1.exec(str3);
console.log(result); // 输出: ["abbb", index: 2, input: "cdabbbcdef", groups: undefined]

// 4. 使用 match() 方法在字符串中查找匹配项
const str4 = 'Is this his AbbBc?';
const regex3 = /abbbc/i; // 'i' 标志表示忽略大小写
console.log(str4.match(regex3)); // 输出: ["AbbBc", index: 12, input: "Is this his AbbBc?", groups: undefined]
```

当 JavaScript 引擎执行这些正则表达式操作时，它会调用 V8 内部的正则表达式实现，其中就包括了 `v8/src/regexp/regexp-parser.cc` 中定义的解析器，将 JavaScript 中的正则表达式字符串解析成内部的 AST 结构。

**代码逻辑推理 (假设输入与输出):**

假设我们有以下简单的正则表达式字符串作为输入：

**假设输入:** `ab+c`

`RegExpParser` (更准确地说是 `RegExpParserImpl` 类) 会逐步解析这个字符串，并构建相应的 AST。以下是一个简化的推理过程：

1. **解析 'a':**  解析器遇到字符 'a'，会创建一个表示字符 'a' 的 `RegExpAtom` 节点。
2. **解析 'b+':**
   - 解析器遇到字符 'b'，会创建一个表示字符 'b' 的 `RegExpAtom` 节点。
   - 解析器遇到量词 '+'，它会作用于之前的 'b'。解析器会创建一个 `RegExpQuantifier` 节点，其最小次数为 1，最大次数为无限大，并将其作用的目标设置为表示 'b' 的 `RegExpAtom` 节点。
3. **解析 'c':** 解析器遇到字符 'c'，会创建一个表示字符 'c' 的 `RegExpAtom` 节点。
4. **组合:**  最后，解析器会将这些节点组合起来，形成一个 `RegExpAlternative` (如果只有一个分支) 或 `RegExpDisjunction` (如果有 `|` 分隔的多个分支) 节点。在这个例子中，会形成一个包含三个连续元素的 `RegExpAlternative` 节点：`RegExpAtom('a')`, `RegExpQuantifier(min=1, max=infinity, target=RegExpAtom('b'))`, `RegExpAtom('c')`。

**假设输出 (AST 结构的简化表示):**

```
RegExpAlternative {
  elements: [
    RegExpAtom { text: "a" },
    RegExpQuantifier { min: 1, max: infinity,  // 或者某个表示无限大的值
                     target: RegExpAtom { text: "b" } },
    RegExpAtom { text: "c" }
  ]
}
```

**用户常见的编程错误举例:**

在正则表达式的使用中，用户常犯一些编程错误，`v8/src/regexp/regexp-parser.cc` 的解析器在解析这些错误时会抛出异常或返回错误信息：

1. **未闭合的分组:**
   ```javascript
   const regex = /ab(c/; // 缺少闭合的括号
   // JavaScript 会抛出 SyntaxError: Invalid regular expression: /ab(c/: Unterminated group
   ```
   解析器在遇到字符串结尾或另一个不期望的字符时，仍然没有找到闭合的 `)`, 就会报错。

2. **无效的转义序列:**
   ```javascript
   const regex = /a\zc/; // \z 不是一个有效的转义序列
   // JavaScript 会抛出 SyntaxError: Invalid regular expression: /a\zc/: Invalid escape
   ```
   解析器会检查反斜杠 `\` 后面的字符是否构成有效的转义序列。

3. **量词的位置错误:**
   ```javascript
   const regex = /a**b/; // 连续的量词
   // JavaScript 会抛出 SyntaxError: Invalid regular expression: /a**b/: Nothing to repeat
   ```
   量词 (`*`, `+`, `?`, `{}`) 必须作用于之前的原子（字符、分组等）。

4. **字符类中未闭合的方括号:**
   ```javascript
   const regex = /ab[c/; // 缺少闭合的方括号
   // JavaScript 会抛出 SyntaxError: Invalid regular expression: /ab[c/: Unterminated character class
   ```
   解析器期待在 `[` 之后找到匹配的 `]`。

5. **使用了不支持的后顾断言 (在不支持的环境中):**
   ```javascript
   const regex = /(?<=a)b/; // 后顾断言在一些旧版本的 JavaScript 引擎中可能不支持
   // 可能会抛出 SyntaxError，取决于 JavaScript 引擎的版本。
   ```
   解析器会根据当前的正则表达式标志和引擎支持的功能来判断语法是否有效。

**总结 `v8/src/regexp/regexp-parser.cc` 的功能 (第 1 部分):**

总而言之，`v8/src/regexp/regexp-parser.cc` 文件是 V8 引擎中至关重要的组成部分，负责将开发者编写的正则表达式字符串转化为引擎可以理解和操作的内部数据结构（AST）。它实现了正则表达式的语法分析逻辑，并负责识别和报告语法错误。这个解析器的正确性和效率直接影响到 JavaScript 中正则表达式的性能和可靠性。它为后续的正则表达式编译和执行阶段奠定了基础。

### 提示词
```
这是目录为v8/src/regexp/regexp-parser.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/regexp-parser.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/regexp/regexp-parser.h"

#include "src/execution/isolate.h"
#include "src/objects/string-inl.h"
#include "src/regexp/regexp-ast.h"
#include "src/regexp/regexp-macro-assembler.h"
#include "src/regexp/regexp.h"
#include "src/strings/char-predicates-inl.h"
#include "src/utils/ostreams.h"
#include "src/utils/utils.h"
#include "src/zone/zone-allocator.h"
#include "src/zone/zone-list-inl.h"

#ifdef V8_INTL_SUPPORT
#include "unicode/uniset.h"
#include "unicode/unistr.h"
#include "unicode/usetiter.h"
#include "unicode/utf16.h"  // For U16_NEXT
#endif                      // V8_INTL_SUPPORT

namespace v8 {
namespace internal {

namespace {

// Whether we're currently inside the ClassEscape production
// (tc39.es/ecma262/#prod-annexB-CharacterEscape).
enum class InClassEscapeState {
  kInClass,
  kNotInClass,
};

// The production used to derive ClassSetOperand.
enum class ClassSetOperandType {
  kClassSetCharacter,
  kClassStringDisjunction,
  kNestedClass,
  kCharacterClassEscape,  // \ CharacterClassEscape is a special nested class,
                          // as we can fold it directly into another range.
  kClassSetRange
};

class RegExpTextBuilder {
 public:
  using SmallRegExpTreeVector = SmallZoneVector<RegExpTree*, 8>;

  RegExpTextBuilder(Zone* zone, SmallRegExpTreeVector* terms_storage,
                    RegExpFlags flags)
      : zone_(zone), flags_(flags), terms_(terms_storage), text_(zone) {}
  void AddCharacter(base::uc16 character);
  void AddUnicodeCharacter(base::uc32 character);
  void AddEscapedUnicodeCharacter(base::uc32 character);
  void AddAtom(RegExpTree* atom);
  void AddTerm(RegExpTree* term);
  void AddClassRanges(RegExpClassRanges* cc);
  void FlushPendingSurrogate();
  void FlushText();
  RegExpTree* PopLastAtom();
  RegExpTree* ToRegExp();

 private:
  static const base::uc16 kNoPendingSurrogate = 0;

  void AddLeadSurrogate(base::uc16 lead_surrogate);
  void AddTrailSurrogate(base::uc16 trail_surrogate);
  void FlushCharacters();
  bool NeedsDesugaringForUnicode(RegExpClassRanges* cc);
  bool NeedsDesugaringForIgnoreCase(base::uc32 c);
  void AddClassRangesForDesugaring(base::uc32 c);
  bool ignore_case() const { return IsIgnoreCase(flags_); }
  bool IsUnicodeMode() const {
    // Either /v or /u enable UnicodeMode
    // https://tc39.es/ecma262/#sec-parsepattern
    return IsUnicode(flags_) || IsUnicodeSets(flags_);
  }
  Zone* zone() const { return zone_; }

  Zone* const zone_;
  const RegExpFlags flags_;
  ZoneList<base::uc16>* characters_ = nullptr;
  base::uc16 pending_surrogate_ = kNoPendingSurrogate;
  SmallRegExpTreeVector* terms_;
  SmallRegExpTreeVector text_;
};

void RegExpTextBuilder::AddLeadSurrogate(base::uc16 lead_surrogate) {
  DCHECK(unibrow::Utf16::IsLeadSurrogate(lead_surrogate));
  FlushPendingSurrogate();
  // Hold onto the lead surrogate, waiting for a trail surrogate to follow.
  pending_surrogate_ = lead_surrogate;
}

void RegExpTextBuilder::AddTrailSurrogate(base::uc16 trail_surrogate) {
  DCHECK(unibrow::Utf16::IsTrailSurrogate(trail_surrogate));
  if (pending_surrogate_ != kNoPendingSurrogate) {
    base::uc16 lead_surrogate = pending_surrogate_;
    pending_surrogate_ = kNoPendingSurrogate;
    DCHECK(unibrow::Utf16::IsLeadSurrogate(lead_surrogate));
    base::uc32 combined =
        unibrow::Utf16::CombineSurrogatePair(lead_surrogate, trail_surrogate);
    if (NeedsDesugaringForIgnoreCase(combined)) {
      AddClassRangesForDesugaring(combined);
    } else {
      ZoneList<base::uc16> surrogate_pair(2, zone());
      surrogate_pair.Add(lead_surrogate, zone());
      surrogate_pair.Add(trail_surrogate, zone());
      RegExpAtom* atom =
          zone()->New<RegExpAtom>(surrogate_pair.ToConstVector());
      AddAtom(atom);
    }
  } else {
    pending_surrogate_ = trail_surrogate;
    FlushPendingSurrogate();
  }
}

void RegExpTextBuilder::FlushPendingSurrogate() {
  if (pending_surrogate_ != kNoPendingSurrogate) {
    DCHECK(IsUnicodeMode());
    base::uc32 c = pending_surrogate_;
    pending_surrogate_ = kNoPendingSurrogate;
    AddClassRangesForDesugaring(c);
  }
}

void RegExpTextBuilder::FlushCharacters() {
  FlushPendingSurrogate();
  if (characters_ != nullptr) {
    RegExpTree* atom = zone()->New<RegExpAtom>(characters_->ToConstVector());
    characters_ = nullptr;
    text_.emplace_back(atom);
  }
}

void RegExpTextBuilder::FlushText() {
  FlushCharacters();
  size_t num_text = text_.size();
  if (num_text == 0) {
    return;
  } else if (num_text == 1) {
    terms_->emplace_back(text_.back());
  } else {
    RegExpText* text = zone()->New<RegExpText>(zone());
    for (size_t i = 0; i < num_text; i++) {
      text_[i]->AppendToText(text, zone());
    }
    terms_->emplace_back(text);
  }
  text_.clear();
}

void RegExpTextBuilder::AddCharacter(base::uc16 c) {
  FlushPendingSurrogate();
  if (characters_ == nullptr) {
    characters_ = zone()->New<ZoneList<base::uc16>>(4, zone());
  }
  characters_->Add(c, zone());
}

void RegExpTextBuilder::AddUnicodeCharacter(base::uc32 c) {
  if (c > static_cast<base::uc32>(unibrow::Utf16::kMaxNonSurrogateCharCode)) {
    DCHECK(IsUnicodeMode());
    AddLeadSurrogate(unibrow::Utf16::LeadSurrogate(c));
    AddTrailSurrogate(unibrow::Utf16::TrailSurrogate(c));
  } else if (IsUnicodeMode() && unibrow::Utf16::IsLeadSurrogate(c)) {
    AddLeadSurrogate(c);
  } else if (IsUnicodeMode() && unibrow::Utf16::IsTrailSurrogate(c)) {
    AddTrailSurrogate(c);
  } else {
    AddCharacter(static_cast<base::uc16>(c));
  }
}

void RegExpTextBuilder::AddEscapedUnicodeCharacter(base::uc32 character) {
  // A lead or trail surrogate parsed via escape sequence will not
  // pair up with any preceding lead or following trail surrogate.
  FlushPendingSurrogate();
  AddUnicodeCharacter(character);
  FlushPendingSurrogate();
}

void RegExpTextBuilder::AddClassRanges(RegExpClassRanges* cr) {
  if (NeedsDesugaringForUnicode(cr)) {
    // With /u or /v, character class needs to be desugared, so it
    // must be a standalone term instead of being part of a RegExpText.
    AddTerm(cr);
  } else {
    AddAtom(cr);
  }
}

void RegExpTextBuilder::AddClassRangesForDesugaring(base::uc32 c) {
  AddTerm(zone()->New<RegExpClassRanges>(
      zone(), CharacterRange::List(zone(), CharacterRange::Singleton(c))));
}

void RegExpTextBuilder::AddAtom(RegExpTree* atom) {
  DCHECK(atom->IsTextElement());
  FlushCharacters();
  text_.emplace_back(atom);
}

void RegExpTextBuilder::AddTerm(RegExpTree* term) {
  DCHECK(term->IsTextElement());
  FlushText();
  terms_->emplace_back(term);
}

bool RegExpTextBuilder::NeedsDesugaringForUnicode(RegExpClassRanges* cc) {
  if (!IsUnicodeMode()) return false;
  // TODO(yangguo): we could be smarter than this. Case-insensitivity does not
  // necessarily mean that we need to desugar. It's probably nicer to have a
  // separate pass to figure out unicode desugarings.
  if (ignore_case()) return true;
  ZoneList<CharacterRange>* ranges = cc->ranges(zone());
  CharacterRange::Canonicalize(ranges);

  if (cc->is_negated()) {
    ZoneList<CharacterRange>* negated_ranges =
        zone()->New<ZoneList<CharacterRange>>(ranges->length(), zone());
    CharacterRange::Negate(ranges, negated_ranges, zone());
    ranges = negated_ranges;
  }

  for (int i = ranges->length() - 1; i >= 0; i--) {
    base::uc32 from = ranges->at(i).from();
    base::uc32 to = ranges->at(i).to();
    // Check for non-BMP characters.
    if (to >= kNonBmpStart) return true;
    // Check for lone surrogates.
    if (from <= kTrailSurrogateEnd && to >= kLeadSurrogateStart) return true;
  }
  return false;
}

// We only use this for characters made of surrogate pairs.  All other
// characters outside of character classes are made case independent in the
// code generation.
bool RegExpTextBuilder::NeedsDesugaringForIgnoreCase(base::uc32 c) {
#ifdef V8_INTL_SUPPORT
  if (IsUnicodeMode() && ignore_case()) {
    icu::UnicodeSet set(c, c);
    set.closeOver(USET_CASE_INSENSITIVE);
    set.removeAllStrings();
    return set.size() > 1;
  }
  // In the case where ICU is not included, we act as if the unicode flag is
  // not set, and do not desugar.
#endif  // V8_INTL_SUPPORT
  return false;
}

RegExpTree* RegExpTextBuilder::PopLastAtom() {
  FlushPendingSurrogate();
  RegExpTree* atom;
  if (characters_ != nullptr) {
    base::Vector<const base::uc16> char_vector = characters_->ToConstVector();
    int num_chars = char_vector.length();
    if (num_chars > 1) {
      base::Vector<const base::uc16> prefix =
          char_vector.SubVector(0, num_chars - 1);
      text_.emplace_back(zone()->New<RegExpAtom>(prefix));
      char_vector = char_vector.SubVector(num_chars - 1, num_chars);
    }
    characters_ = nullptr;
    atom = zone()->New<RegExpAtom>(char_vector);
    return atom;
  } else if (!text_.empty()) {
    atom = text_.back();
    text_.pop_back();
    return atom;
  }
  return nullptr;
}

RegExpTree* RegExpTextBuilder::ToRegExp() {
  FlushText();
  size_t num_alternatives = terms_->size();
  if (num_alternatives == 0) return zone()->New<RegExpEmpty>();
  if (num_alternatives == 1) return terms_->back();
  return zone()->New<RegExpAlternative>(zone()->New<ZoneList<RegExpTree*>>(
      base::VectorOf(terms_->begin(), terms_->size()), zone()));
}

// Accumulates RegExp atoms and assertions into lists of terms and alternatives.
class RegExpBuilder {
 public:
  RegExpBuilder(Zone* zone, RegExpFlags flags)
      : zone_(zone),
        flags_(flags),
        terms_(zone),
        alternatives_(zone),
        text_builder_(RegExpTextBuilder{zone, &terms_, flags}) {}
  void AddCharacter(base::uc16 character);
  void AddUnicodeCharacter(base::uc32 character);
  void AddEscapedUnicodeCharacter(base::uc32 character);
  // "Adds" an empty expression. Does nothing except consume a
  // following quantifier
  void AddEmpty();
  void AddClassRanges(RegExpClassRanges* cc);
  void AddAtom(RegExpTree* tree);
  void AddTerm(RegExpTree* tree);
  void AddAssertion(RegExpTree* tree);
  void NewAlternative();  // '|'
  bool AddQuantifierToAtom(int min, int max, int index,
                           RegExpQuantifier::QuantifierType type);
  void FlushText();
  RegExpTree* ToRegExp();
  RegExpFlags flags() const { return flags_; }

  bool ignore_case() const { return IsIgnoreCase(flags_); }
  bool multiline() const { return IsMultiline(flags_); }
  bool dotall() const { return IsDotAll(flags_); }

 private:
  void FlushTerms();
  bool IsUnicodeMode() const {
    // Either /v or /u enable UnicodeMode
    // https://tc39.es/ecma262/#sec-parsepattern
    return IsUnicode(flags_) || IsUnicodeSets(flags_);
  }
  Zone* zone() const { return zone_; }
  RegExpTextBuilder& text_builder() { return text_builder_; }

  Zone* const zone_;
  bool pending_empty_ = false;
  const RegExpFlags flags_;

  using SmallRegExpTreeVector = SmallZoneVector<RegExpTree*, 8>;
  SmallRegExpTreeVector terms_;
  SmallRegExpTreeVector alternatives_;
  RegExpTextBuilder text_builder_;
};

enum SubexpressionType {
  INITIAL,
  CAPTURE,  // All positive values represent captures.
  POSITIVE_LOOKAROUND,
  NEGATIVE_LOOKAROUND,
  GROUPING
};

class RegExpParserState : public ZoneObject {
 public:
  // Push a state on the stack.
  RegExpParserState(RegExpParserState* previous_state,
                    SubexpressionType group_type,
                    RegExpLookaround::Type lookaround_type,
                    int disjunction_capture_index,
                    const ZoneVector<base::uc16>* capture_name,
                    RegExpFlags flags, Zone* zone)
      : previous_state_(previous_state),
        builder_(zone, flags),
        group_type_(group_type),
        lookaround_type_(lookaround_type),
        disjunction_capture_index_(disjunction_capture_index),
        capture_name_(capture_name) {
    if (previous_state != nullptr) {
      non_participating_capture_group_interval_ =
          previous_state->non_participating_capture_group_interval();
    }
  }
  // Parser state of containing expression, if any.
  RegExpParserState* previous_state() const { return previous_state_; }
  bool IsSubexpression() { return previous_state_ != nullptr; }
  // RegExpBuilder building this regexp's AST.
  RegExpBuilder* builder() { return &builder_; }
  // Type of regexp being parsed (parenthesized group or entire regexp).
  SubexpressionType group_type() const { return group_type_; }
  // Lookahead or Lookbehind.
  RegExpLookaround::Type lookaround_type() const { return lookaround_type_; }
  // Index in captures array of first capture in this sub-expression, if any.
  // Also the capture index of this sub-expression itself, if group_type
  // is CAPTURE.
  int capture_index() const { return disjunction_capture_index_; }
  // The name of the current sub-expression, if group_type is CAPTURE. Only
  // used for named captures.
  const ZoneVector<base::uc16>* capture_name() const { return capture_name_; }
  std::pair<int, int> non_participating_capture_group_interval() const {
    return non_participating_capture_group_interval_;
  }

  bool IsNamedCapture() const { return capture_name_ != nullptr; }

  // Check whether the parser is inside a capture group with the given index.
  bool IsInsideCaptureGroup(int index) const {
    for (const RegExpParserState* s = this; s != nullptr;
         s = s->previous_state()) {
      if (s->group_type() != CAPTURE) continue;
      // Return true if we found the matching capture index.
      if (index == s->capture_index()) return true;
      // Abort if index is larger than what has been parsed up till this state.
      if (index > s->capture_index()) return false;
    }
    return false;
  }

  // Check whether the parser is inside a capture group with the given name.
  bool IsInsideCaptureGroup(const ZoneVector<base::uc16>* name) const {
    DCHECK_NOT_NULL(name);
    for (const RegExpParserState* s = this; s != nullptr;
         s = s->previous_state()) {
      if (s->capture_name() == nullptr) continue;
      if (*s->capture_name() == *name) return true;
    }
    return false;
  }

  void NewAlternative(int captures_started) {
    if (non_participating_capture_group_interval().second != 0) {
      // Extend the non-participating interval.
      non_participating_capture_group_interval_.second = captures_started;
    } else {
      // Create new non-participating interval from the start of the current
      // enclosing group to all captures created within that group so far.
      non_participating_capture_group_interval_ =
          std::make_pair(capture_index(), captures_started);
    }
  }

 private:
  // Linked list implementation of stack of states.
  RegExpParserState* const previous_state_;
  // Builder for the stored disjunction.
  RegExpBuilder builder_;
  // Stored disjunction type (capture, look-ahead or grouping), if any.
  const SubexpressionType group_type_;
  // Stored read direction.
  const RegExpLookaround::Type lookaround_type_;
  // Stored disjunction's capture index (if any).
  const int disjunction_capture_index_;
  // Stored capture name (if any).
  const ZoneVector<base::uc16>* const capture_name_;
  // Interval of (named) capture indices ]from, to] that are not participating
  // in the current state (i.e. they cannot match).
  // Capture indices are not participating if they were created in a different
  // alternative.
  std::pair<int, int> non_participating_capture_group_interval_;
};

template <class CharT>
class RegExpParserImpl final {
 private:
  RegExpParserImpl(const CharT* input, int input_length, RegExpFlags flags,
                   uintptr_t stack_limit, Zone* zone,
                   const DisallowGarbageCollection& no_gc);

  bool Parse(RegExpCompileData* result);

  RegExpTree* ParsePattern();
  RegExpTree* ParseDisjunction();
  RegExpTree* ParseGroup();

  // Parses a {...,...} quantifier and stores the range in the given
  // out parameters.
  bool ParseIntervalQuantifier(int* min_out, int* max_out);

  // Checks whether the following is a length-digit hexadecimal number,
  // and sets the value if it is.
  bool ParseHexEscape(int length, base::uc32* value);
  bool ParseUnicodeEscape(base::uc32* value);
  bool ParseUnlimitedLengthHexNumber(int max_value, base::uc32* value);

  bool ParsePropertyClassName(ZoneVector<char>* name_1,
                              ZoneVector<char>* name_2);
  bool AddPropertyClassRange(ZoneList<CharacterRange>* add_to_range,
                             CharacterClassStrings* add_to_strings, bool negate,
                             const ZoneVector<char>& name_1,
                             const ZoneVector<char>& name_2);

  RegExpTree* ParseClassRanges(ZoneList<CharacterRange>* ranges,
                               bool add_unicode_case_equivalents);
  // Parse inside a class. Either add escaped class to the range, or return
  // false and pass parsed single character through |char_out|.
  void ParseClassEscape(ZoneList<CharacterRange>* ranges, Zone* zone,
                        bool add_unicode_case_equivalents, base::uc32* char_out,
                        bool* is_class_escape);
  // Returns true iff parsing was successful.
  bool TryParseCharacterClassEscape(base::uc32 next,
                                    InClassEscapeState in_class_escape_state,
                                    ZoneList<CharacterRange>* ranges,
                                    CharacterClassStrings* strings, Zone* zone,
                                    bool add_unicode_case_equivalents);
  RegExpTree* ParseClassStringDisjunction(ZoneList<CharacterRange>* ranges,
                                          CharacterClassStrings* strings);
  RegExpTree* ParseClassSetOperand(const RegExpBuilder* builder,
                                   ClassSetOperandType* type_out);
  RegExpTree* ParseClassSetOperand(const RegExpBuilder* builder,
                                   ClassSetOperandType* type_out,
                                   ZoneList<CharacterRange>* ranges,
                                   CharacterClassStrings* strings,
                                   base::uc32* character);
  base::uc32 ParseClassSetCharacter();
  // Parses and returns a single escaped character.
  base::uc32 ParseCharacterEscape(InClassEscapeState in_class_escape_state,
                                  bool* is_escaped_unicode_character);

  void AddMaybeSimpleCaseFoldedRange(ZoneList<CharacterRange>* ranges,
                                     CharacterRange new_range);

  RegExpTree* ParseClassUnion(const RegExpBuilder* builder, bool is_negated,
                              RegExpTree* first_operand,
                              ClassSetOperandType first_operand_type,
                              ZoneList<CharacterRange>* ranges,
                              CharacterClassStrings* strings,
                              base::uc32 first_character);
  RegExpTree* ParseClassIntersection(const RegExpBuilder* builder,
                                     bool is_negated, RegExpTree* first_operand,
                                     ClassSetOperandType first_operand_type);
  RegExpTree* ParseClassSubtraction(const RegExpBuilder* builder,
                                    bool is_negated, RegExpTree* first_operand,
                                    ClassSetOperandType first_operand_type);
  RegExpTree* ParseCharacterClass(const RegExpBuilder* state);

  base::uc32 ParseOctalLiteral();

  // Tries to parse the input as a back reference.  If successful it
  // stores the result in the output parameter and returns true.  If
  // it fails it will push back the characters read so the same characters
  // can be reparsed.
  bool ParseBackReferenceIndex(int* index_out);

  RegExpTree* ReportError(RegExpError error);
  void Advance();
  void Advance(int dist);
  void RewindByOneCodepoint();  // Rewinds to before the previous Advance().
  void Reset(int pos);

  // Reports whether the pattern might be used as a literal search string.
  // Only use if the result of the parse is a single atom node.
  bool simple() const { return simple_; }
  bool contains_anchor() const { return contains_anchor_; }
  void set_contains_anchor() { contains_anchor_ = true; }
  int captures_started() const { return captures_started_; }
  int position() const { return next_pos_ - 1; }
  bool failed() const { return failed_; }
  RegExpFlags flags() const { return flags_; }
  bool IsUnicodeMode() const {
    // Either /v or /u enable UnicodeMode
    // https://tc39.es/ecma262/#sec-parsepattern
    return IsUnicode(flags()) || IsUnicodeSets(flags()) || force_unicode_;
  }
  bool unicode_sets() const { return IsUnicodeSets(flags()); }
  bool ignore_case() const { return IsIgnoreCase(flags()); }

  static bool IsSyntaxCharacterOrSlash(base::uc32 c);
  static bool IsClassSetSyntaxCharacter(base::uc32 c);
  static bool IsClassSetReservedPunctuator(base::uc32 c);
  bool IsClassSetReservedDoublePunctuator(base::uc32 c);

  static const base::uc32 kEndMarker = (1 << 21);

 private:
  // Return the 1-indexed RegExpCapture object, allocate if necessary.
  RegExpCapture* GetCapture(int index);

  // Creates a new named capture at the specified index. Must be called exactly
  // once for each named capture. Fails if a capture with the same name is
  // encountered.
  bool CreateNamedCaptureAtIndex(const RegExpParserState* state, int index);

  // Parses the name of a capture group (?<name>pattern). The name must adhere
  // to IdentifierName in the ECMAScript standard.
  const ZoneVector<base::uc16>* ParseCaptureGroupName();

  bool ParseNamedBackReference(RegExpBuilder* builder,
                               RegExpParserState* state);
  RegExpParserState* ParseOpenParenthesis(RegExpParserState* state);

  // After the initial parsing pass, patch corresponding RegExpCapture objects
  // into all RegExpBackReferences. This is done after initial parsing in order
  // to avoid complicating cases in which references comes before the capture.
  void PatchNamedBackReferences();

  ZoneVector<RegExpCapture*>* GetNamedCaptures();

  // Returns true iff the pattern contains named captures. May call
  // ScanForCaptures to look ahead at the remaining pattern.
  bool HasNamedCaptures(InClassEscapeState in_class_escape_state);

  Zone* zone() const { return zone_; }

  base::uc32 current() const { return current_; }
  bool has_more() const { return has_more_; }
  bool has_next() const { return next_pos_ < input_length(); }
  base::uc32 Next();
  template <bool update_position>
  base::uc32 ReadNext();
  CharT InputAt(int index) const {
    DCHECK(0 <= index && index < input_length());
    return input_[index];
  }
  int input_length() const { return input_length_; }
  void ScanForCaptures(InClassEscapeState in_class_escape_state);

  struct RegExpCaptureNameLess {
    bool operator()(const RegExpCapture* lhs, const RegExpCapture* rhs) const {
      DCHECK_NOT_NULL(lhs);
      DCHECK_NOT_NULL(rhs);
      return *lhs->name() < *rhs->name();
    }
  };

  class ForceUnicodeScope final {
   public:
    explicit ForceUnicodeScope(RegExpParserImpl<CharT>* parser)
        : parser_(parser) {
      DCHECK(!parser_->force_unicode_);
      parser_->force_unicode_ = true;
    }
    ~ForceUnicodeScope() {
      DCHECK(parser_->force_unicode_);
      parser_->force_unicode_ = false;
    }

   private:
    RegExpParserImpl<CharT>* const parser_;
  };

  const DisallowGarbageCollection no_gc_;
  Zone* const zone_;
  RegExpError error_ = RegExpError::kNone;
  int error_pos_ = 0;
  ZoneList<RegExpCapture*>* captures_;
  // Maps capture names to a list of capture indices with this name.
  ZoneMap<RegExpCapture*, ZoneList<int>*, RegExpCaptureNameLess>*
      named_captures_;
  ZoneList<RegExpBackReference*>* named_back_references_;
  ZoneList<CharacterRange>* temp_ranges_;
  const CharT* const input_;
  const int input_length_;
  base::uc32 current_;
  RegExpFlags flags_;
  bool force_unicode_ = false;  // Force parser to act as if unicode were set.
  int next_pos_;
  int captures_started_;
  int capture_count_;  // Only valid after we have scanned for captures.
  int quantifier_count_;
  int lookaround_count_;  // Only valid after we have scanned for lookbehinds.
  bool has_more_;
  bool simple_;
  bool contains_anchor_;
  bool is_scanned_for_captures_;
  bool has_named_captures_;  // Only valid after we have scanned for captures.
  bool failed_;
  const uintptr_t stack_limit_;

  friend class v8::internal::RegExpParser;
};

template <class CharT>
RegExpParserImpl<CharT>::RegExpParserImpl(
    const CharT* input, int input_length, RegExpFlags flags,
    uintptr_t stack_limit, Zone* zone, const DisallowGarbageCollection& no_gc)
    : zone_(zone),
      captures_(nullptr),
      named_captures_(nullptr),
      named_back_references_(nullptr),
      input_(input),
      input_length_(input_length),
      current_(kEndMarker),
      flags_(flags),
      next_pos_(0),
      captures_started_(0),
      capture_count_(0),
      quantifier_count_(0),
      lookaround_count_(0),
      has_more_(true),
      simple_(false),
      contains_anchor_(false),
      is_scanned_for_captures_(false),
      has_named_captures_(false),
      failed_(false),
      stack_limit_(stack_limit) {
  Advance();
}

template <>
template <bool update_position>
inline base::uc32 RegExpParserImpl<uint8_t>::ReadNext() {
  int position = next_pos_;
  base::uc16 c0 = InputAt(position);
  position++;
  DCHECK(!unibrow::Utf16::IsLeadSurrogate(c0));
  if (update_position) next_pos_ = position;
  return c0;
}

template <>
template <bool update_position>
inline base::uc32 RegExpParserImpl<base::uc16>::ReadNext() {
  int position = next_pos_;
  base::uc16 c0 = InputAt(position);
  base::uc32 result = c0;
  position++;
  // Read the whole surrogate pair in case of unicode mode, if possible.
  if (IsUnicodeMode() && position < input_length() &&
      unibrow::Utf16::IsLeadSurrogate(c0)) {
    base::uc16 c1 = InputAt(position);
    if (unibrow::Utf16::IsTrailSurrogate(c1)) {
      result = unibrow::Utf16::CombineSurrogatePair(c0, c1);
      position++;
    }
  }
  if (update_position) next_pos_ = position;
  return result;
}

template <class CharT>
base::uc32 RegExpParserImpl<CharT>::Next() {
  if (has_next()) {
    return ReadNext<false>();
  } else {
    return kEndMarker;
  }
}

template <class CharT>
void RegExpParserImpl<CharT>::Advance() {
  if (has_next()) {
    if (GetCurrentStackPosition() < stack_limit_) {
      if (v8_flags.correctness_fuzzer_suppressions) {
        FATAL("Aborting on stack overflow");
      }
      ReportError(RegExpError::kStackOverflow);
    } else {
      current_ = ReadNext<true>();
    }
  } else {
    current_ = kEndMarker;
    // Advance so that position() points to 1-after-the-last-character. This is
    // important so that Reset() to this position works correctly.
    next_pos_ = input_length() + 1;
    has_more_ = false;
  }
}

template <class CharT>
void RegExpParserImpl<CharT>::RewindByOneCodepoint() {
  if (!has_more()) return;
  // Rewinds by one code point, i.e.: two code units if `current` is outside
  // the basic multilingual plane (= composed of a lead and trail surrogate),
  // or one code unit otherwise.
  const int rewind_by =
      current() > unibrow::Utf16::kMaxNonSurrogateCharCode ? -2 : -1;
  Advance(rewind_by);  // Undo the last Advance.
}

template <class CharT>
void RegExpParserImpl<CharT>::Reset(int pos) {
  next_pos_ = pos;
  has_more_ = (pos < input_length());
  Advance();
}

template <class CharT>
void RegExpParserImpl<CharT>::Advance(int dist) {
  next_pos_ += dist - 1;
  Advance();
}

// static
template <class CharT>
bool RegExpParserImpl<CharT>::IsSyntaxCharacterOrSlash(base::uc32 c) {
  switch (c) {
    case '^':
    case '$':
    case '\\':
    case '.':
    case '*':
    case '+':
    case '?':
    case '(':
    case ')':
    case '[':
    case ']':
    case '{':
    case '}':
    case '|':
    case '/':
      return true;
    default:
      break;
  }
  return false;
}

// static
template <class CharT>
bool RegExpParserImpl<CharT>::IsClassSetSyntaxCharacter(base::uc32 c) {
  switch (c) {
    case '(':
    case ')':
    case '[':
    case ']':
    case '{':
    case '}':
    case '/':
    case '-':
    case '\\':
    case '|':
      return true;
    default:
      break;
  }
  return false;
}

// static
template <class CharT>
bool RegExpParserImpl<CharT>::IsClassSetReservedPunctuator(base::uc32 c) {
  switch (c) {
    case '&':
    case '-':
    case '!':
    case '#':
    case '%':
    case ',':
    case ':':
    case ';':
    case '<':
    case '=':
    case '>':
    case '@':
    case '`':
    case '~':
      return true;
    default:
      break;
  }
  return false;
}

template <class CharT>
bool RegExpParserImpl<CharT>::IsClassSetReservedDoublePunctuator(base::uc32 c) {
#define DOUBLE_PUNCTUATOR_CASE(Char) \
  case Char:                         \
    return Next() == Char

  switch (c) {
    DOUBLE_PUNCTUATOR_CASE('&');
    DOUBLE_PUNCTUATOR_CASE('!');
    DOUBLE_PUNCTUATOR_CASE('#');
    DOUBLE_PUNCTUATOR_CASE('$');
    DOUBLE_PUNCTUATOR_CASE('%');
    DOUBLE_PUNCTUATOR_CASE('*');
    DOUBLE_PUNCTUATOR_CASE('+');
    DOUBLE_PUNCTUATOR_CASE(',');
    DOUBLE_PUNCTUATOR_CASE('.');
    DOUBLE_PUNCTUATOR_CASE(':');
    DOUBLE_PUNCTUATOR_CASE(';');
    DOUBLE_PUNCTUATOR_CASE('<');
    DOUBLE_PUNCTUATOR_CASE('=');
    DOUBLE_PUNCTUATOR_CASE('>');
    DOUBLE_PUNCTUATOR_CASE('?');
    DOUBLE_PUNCTUATOR_CASE('@');
    DOUBLE_PUNCTUATOR_CASE('^');
    DOUBLE_PUNCTUATOR_CASE('`');
    DOUBLE_PUNCTUATOR_CASE('~');
    default:
      break;
  }
#undef DOUBLE_PUNCTUATOR_CASE

  return false;
}

template <class CharT>
RegExpTree* RegExpParserImpl<CharT>::ReportError(RegExpError error) {
  if (failed_) return nullptr;  // Do not overwrite any existing error.
  failed_ = true;
  error_ = error;
  error_pos_ = position();
  // Zip to the end to make sure no more input is read.
  current_ = kEndMarker;
  next_pos_ = input_length();
  has_more_ = false;
  return nullptr;
}

#define CHECK_FAILED /**/);    \
  if (failed_) return nullptr; \
  ((void)0

// Pattern ::
//   Disjunction
template <class CharT>
RegExpTree* RegExpParserImpl<CharT>::ParsePattern() {
  RegExpTree* result = ParseDisjunction(CHECK_FAILED);
  PatchNamedBackReferences(CHECK_FAILED);
  DCHECK(!has_more());
  // If the result of parsing is a literal string atom, and it has the
  // same length as the input, then the atom is identical to the input.
  if (result->IsAtom() && result->AsAtom()->length() == input_length()) {
    simple_ = true;
  }
  return result;
}

// Disjunction ::
//   Alternative
//   Alternative | Disjunction
// Alternative ::
//   [empty]
//   Term Alternative
// Term ::
//   Assertion
//   Atom
//   Atom Quantifier
template <class CharT>
RegExpTree* RegExpParserImpl<CharT>::ParseDisjunction() {
  // Used to store current state while parsing subexpressions.
  RegExpParserState initial_state(nullptr, INITIAL, RegExpLookaround::LOOKAHEAD,
                                  0, nullptr, flags(), zone());
  RegExpParserState* state = &initial_state;
  // Cache the builder in a local variable for quick access.
  RegExpBuilder* builder = initial_state.builder();
  while (true) {
    switch (current()) {
      case kEndMarker:
        if (failed()) return nullptr;  // E.g. the initial Advance failed.
        if (state->IsSubexpression()) {
          // Inside a parenthesized group when hitting end of input.
          return ReportError(RegExpError::kUnterminatedGroup);
        }
        DCHECK_EQ(INITIAL, state->group_type());
        // Parsing completed successfully.
        return builder->ToRegExp();
      case ')': {
        if (!state->IsSubexpression()) {
          return ReportError(RegExpError::kUnmatchedParen);
        }
        DCHECK_NE(INITIAL, state->group_type());

        Advance();
        // End disjunction parsing and convert builder content to new single
        // regexp atom.
        RegExpTree* body = builder->ToRegExp();

        int end_capture_index = captures_started();

        int capture_index = state->capture_index();
        SubexpressionType group_type = state->group_type();

        // Build result of subexpression.
        if (group_type == CAPTURE) {
          if (state->IsNamedCapture()) {
            CreateNamedCaptureAtIndex(state, capture_index CHECK_FAILED);
          }
          RegExpCapture* capture = GetCapture(capture_index);
          capture->set_body(body);
          body = capture;
        } else if (group_type == GROUPING)
```