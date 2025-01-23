Response:
Let's break down the thought process to analyze the provided C++ code snippet for a regular expression parser.

**1. Initial Understanding of the Request:**

The request asks for the functionality of the provided C++ code, specifically focusing on its role as a regular expression parser within the V8 JavaScript engine. It also asks to consider hypothetical scenarios (Torque, JavaScript relation), code logic inference, common errors, and a final summary.

**2. High-Level Overview of the Code:**

The code is within the `v8::internal` namespace and the `RegExpParserImpl` template class. This immediately suggests it's part of V8's internal regular expression handling. The template indicates it handles both narrow (uint8_t) and wide (base::uc16) character representations, which is typical for handling both ASCII and Unicode inputs. The methods like `ParseClassUnion`, `ParseClassIntersection`, `ParseClassSubtraction`, and `ParseCharacterClass` strongly suggest the code is responsible for parsing the character class constructs within regular expressions.

**3. Deconstructing Key Functions and Data Structures:**

* **`RegExpParserImpl`:** This is the core class. It holds the parsing state (current position, flags, error information). The template nature is important to note.
* **`Parse*` methods (e.g., `ParseClassUnion`, `ParseClassIntersection`, etc.):**  These are clearly responsible for parsing specific grammar rules of regular expressions, particularly those related to character classes and set operations. The naming is very descriptive.
* **`RegExpBuilder`:** This class seems to be responsible for building the Abstract Syntax Tree (AST) representation of the regular expression as it's being parsed. Methods like `AddCharacter`, `AddAtom`, `AddQuantifierToAtom`, and `ToRegExp` strongly suggest this.
* **`RegExpTree` and its subclasses (e.g., `RegExpClassSetExpression`, `RegExpClassRanges`, `RegExpQuantifier`, etc.):** These represent the nodes in the regular expression AST. The different subclasses represent different components of a regular expression.
* **`CharacterRange` and `CharacterClassStrings`:** These data structures are used to represent the ranges of characters and individual strings within character classes.
* **`RegExpCompileData`:**  This structure likely holds the final parsed representation of the regular expression, including the AST and other metadata.

**4. Analyzing Specific Code Blocks:**

* **Character Class Parsing (e.g., `ParseClassUnion`):**  The code iterates through the characters within a `[...]` block. It handles ranges, set operations (`--`, `&&`), and negation (`^`). The logic for handling `may_contain_strings` and the error for negated classes with strings are important details.
* **Class Set Operations:**  The `ParseClassIntersection` and `ParseClassSubtraction` methods specifically handle the `&&` and `--` operators within character classes, a relatively recent addition to JavaScript regular expressions.
* **`ParseCharacterClass`:** This acts as a dispatcher for different kinds of character class parsing based on the presence of Unicode set notation.
* **`RegExpBuilder` Methods:**  Understanding how the `RegExpBuilder` accumulates characters and terms before constructing higher-level expressions is crucial. The `FlushText()` method suggests the builder handles contiguous text efficiently.

**5. Answering the Specific Questions:**

* **Functionality:** Based on the function names and the overall structure, the primary function is parsing regular expression syntax, especially character classes, and building an internal representation (AST).
* **Torque:** The prompt explicitly mentions ".tq". Since the file ends in ".cc", it's a C++ file, *not* a Torque file. Torque is a TypeScript-like language for V8's internal implementation.
* **JavaScript Relation:** This is where we connect the C++ code to user-facing JavaScript. Character classes are a fundamental part of JavaScript regular expressions. Provide examples of character classes and the set operations.
* **Code Logic Inference:** Focus on the character class parsing logic. Choose a simple example like `[a-z]` or a more complex one with set operations like `[a-z&&[^bc]]`. Trace the potential flow through `ParseCharacterClass`, `ParseClassUnion`, and the handling of `CharacterRange`. Predict the output would be an `RegExpClassSetExpression` representing the union of the character ranges.
* **Common Programming Errors:** Think about common mistakes users make with character classes, such as unescaped special characters, forgetting to close the `]` bracket, or incorrect usage of set operations.
* **Summary:**  Synthesize the findings into a concise summary highlighting the key role of this code in V8's regular expression engine.

**6. Refining and Organizing the Answer:**

Structure the answer clearly, using headings for each part of the request. Provide specific code examples in JavaScript where relevant. Explain the purpose of key data structures and classes. Ensure the language is precise and avoids unnecessary jargon where possible.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the code handles *all* aspects of regex parsing.
* **Correction:**  The focus seems heavily on character classes and set operations. Other parts of regex parsing (quantifiers, anchors, etc.) might be handled in other files, though `RegExpBuilder` touches on quantifiers.
* **Initial thought:** Just describe the functions.
* **Refinement:** Explain *why* these functions are needed in the context of regular expression parsing and how they relate to the JavaScript syntax.

By following this detailed analysis, breaking down the code into smaller parts, and relating it to the specific questions in the prompt, we arrive at a comprehensive and accurate answer.
这是对 V8 源代码文件 `v8/src/regexp/regexp-parser.cc` 的功能进行的详细分析，特别是关于字符类解析部分。

**功能归纳:**

这个代码片段主要负责 V8 引擎中正则表达式的字符类（Character Class）部分的解析。它将正则表达式中 `[...]`  结构内的字符、字符范围、预定义字符类（如 `\d`, `\w`）、Unicode 属性、以及字符类之间的集合运算（并集、交集、差集）解析成内部的抽象语法树 (AST) 节点，以便后续的正则表达式编译和执行。

**具体功能分解:**

1. **解析字符类语法:**
   - 识别并处理字符类的开始和结束标记 `[` 和 `]`。
   - 处理字符类中的否定操作符 `^`。
   - 解析单个字符和转义字符。
   - 解析字符范围，例如 `a-z`。
   - 处理 Unicode 属性转义，例如 `\p{...}` 和 `\P{...}`。

2. **处理字符类集合运算 (Unicode Sets 特性):**
   - 解析字符类的并集（隐式，连续的字符或范围）。
   - 解析字符类的交集运算 `&&`。
   - 解析字符类的差集运算 `--`。

3. **构建正则表达式 AST:**
   - 创建 `RegExpClassRanges` 节点来表示简单的字符范围集合（非 Unicode Sets 模式）。
   - 创建 `RegExpClassSetExpression` 节点来表示包含集合运算的更复杂的字符类。
   - 使用 `RegExpClassSetOperand` 来表示字符类运算的单个操作数（可以是字符范围或字符串）。

4. **错误处理:**
   - 检测并报告字符类中常见的语法错误，例如未终止的字符类 (`kUnterminatedCharacterClass`) 或在否定字符类中使用字符串 (`kNegatedCharacterClassWithStrings`)。
   - 检测并报告无效的字符类集合运算 (`kInvalidClassSetOperation`)。

5. **与 `RegExpBuilder` 协同:**
   - `RegExpParserImpl` 使用 `RegExpBuilder` 来逐步构建正则表达式的 AST。当解析到一个完整的字符类后，会将其作为一个 `RegExpTree` 添加到 `RegExpBuilder` 中。

**关于 .tq 后缀:**

如果 `v8/src/regexp/regexp-parser.cc` 的文件名以 `.tq` 结尾，那么它将是 **V8 Torque 源代码**。Torque 是一种用于编写 V8 内部实现的领域特定语言，它允许更安全、更高效的底层代码生成。  然而，根据您提供的信息，该文件名为 `.cc`，因此它是 **C++ 源代码**。

**与 JavaScript 的关系 (举例):**

JavaScript 中的正则表达式广泛使用了字符类。  以下是一些与这段 C++ 代码功能相关的 JavaScript 正则表达式示例：

```javascript
// 简单的字符范围
const regex1 = /[a-z]/; // 匹配小写字母 a 到 z

// 否定字符类
const regex2 = /[^0-9]/; // 匹配任何非数字字符

// 包含转义字符
const regex3 = /[a-zA-Z0-9_]/; // 匹配字母、数字或下划线

// Unicode 属性 (需要 /u 标志)
const regex4 = /\p{Letter}/u; // 匹配任何字母字符 (Unicode)
const regex5 = /\P{Number}/u; // 匹配任何非数字字符 (Unicode)

// 字符类集合运算 (需要 /v 标志，或 /u 标志和特定的提案支持)
const regex6 = /[a-z&&[^aeiou]]/v; // 匹配小写辅音字母 (a-z 且 不是 a, e, i, o, u)
const regex7 = /[0-9--[357]]/v; // 匹配数字 0-9，但不包括 3, 5, 7
```

当 V8 引擎执行这些 JavaScript 正则表达式时，`v8/src/regexp/regexp-parser.cc` 中的代码（或者其 Torque 等价物，如果存在）会被调用来解析这些字符类的语法，并构建内部表示。

**代码逻辑推理 (假设输入与输出):**

**假设输入 (正则表达式字符串片段):** `"[a-zA-Z0-9_]"`

**处理流程 (简化):**

1. `ParseCharacterClass` 函数被调用，识别到 `[` 开始。
2. 循环读取字符，识别到 `a-z`，创建表示该范围的 `CharacterRange`。
3. 识别到 `A-Z`，创建另一个 `CharacterRange`。
4. 识别到 `0-9`，创建又一个 `CharacterRange`。
5. 识别到 `_`，创建一个表示单个字符的 `CharacterRange`。
6. 识别到 `]` 结束。
7. 如果没有使用 Unicode Sets 特性，可能会创建一个 `RegExpClassRanges` 对象，包含这些范围。
8. 如果启用了 Unicode Sets，可能会创建一个 `RegExpClassSetExpression` 对象，其操作类型为 `kUnion`，操作数是包含这些范围的 `RegExpClassSetOperand`。

**假设输出 (近似的 AST 结构):**

```
RegExpClassSetExpression {
  operation_type: kUnion,
  is_negated: false,
  may_contain_strings: false,
  operands: [
    RegExpClassSetOperand { ranges: [a-z] },
    RegExpClassSetOperand { ranges: [A-Z] },
    RegExpClassSetOperand { ranges: [0-9] },
    RegExpClassSetOperand { ranges: [_] }
  ]
}
```

**涉及用户常见的编程错误 (举例):**

1. **未闭合的字符类:** `/[a-z/`  - 这会导致 `ReportError(RegExpError::kUnterminatedCharacterClass)`。JavaScript 会抛出一个 `SyntaxError: Invalid regular expression: /[a-z/: Unterminated character class`。

2. **在否定字符类中使用字符串 (在不支持 Unicode Sets 的旧引擎中可能有效，但在支持 Unicode Sets 的引擎中会报错):** `/[^abc]/` (这个在大多数引擎中是合法的，但在启用 Unicode Sets 的情况下，如果将其视为字符串集合，则否定操作会报错)。然而，代码中 `kNegatedCharacterClassWithStrings` 更可能指的是在明确使用 Unicode Sets 语法时，尝试否定一个包含字符串的集合，例如 `/[^\q{abc}]/v`。  JavaScript 可能会抛出 `SyntaxError: Invalid regular expression: /[^\q{abc}]/v: Negated character class cannot contain strings`。

3. **错误的字符类集合运算语法:** `/[a-z & [0-9]]/v` (应该使用 `&&`) - 这会导致 `ReportError(RegExpError::kInvalidClassSetOperation)`。 JavaScript 会抛出 `SyntaxError: Invalid regular expression: /[a-z & [0-9]]/v/: Invalid character class`。

4. **忘记转义特殊字符:** `/[.*]/` (本意是匹配字面量 `.` 或 `*`) - 这会被解析为匹配任意字符 (对于 `.`) 和匹配前面的元素零次或多次 (对于 `*`)，而不是字面量。正确的写法是 `/[\\.*]/`。

**总结 `v8/src/regexp/regexp-parser.cc` (本代码片段) 的功能:**

总而言之，这段代码是 V8 引擎正则表达式解析器的核心组成部分，专门负责解析正则表达式中字符类的语法，包括基本字符、范围、预定义类、Unicode 属性以及字符类集合运算。它将这些语法结构转化为 V8 内部的 AST 表示，为后续的正则表达式编译和执行奠定基础。它还负责检测和报告与字符类相关的常见语法错误，帮助开发者编写正确的正则表达式。

### 提示词
```
这是目录为v8/src/regexp/regexp-parser.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/regexp-parser.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
may_contain_strings |= !strings->empty();
          operands->Add(
              zone()->template New<RegExpClassSetOperand>(ranges, strings),
              zone());
          ranges = zone()->template New<ZoneList<CharacterRange>>(2, zone());
          strings = zone()->template New<CharacterClassStrings>(zone());
        }
        operands->Add(operand, zone());
      }
    }
  }

  if (!has_more()) {
    return ReportError(RegExpError::kUnterminatedCharacterClass);
  }

  if (last_type == ClassSetOperandType::kClassSetCharacter) {
    AddMaybeSimpleCaseFoldedRange(ranges, CharacterRange::Singleton(character));
  }

  // Add the range we started building as operand.
  if (!ranges->is_empty() || !strings->empty()) {
    may_contain_strings |= !strings->empty();
    operands->Add(zone()->template New<RegExpClassSetOperand>(ranges, strings),
                  zone());
  }

  DCHECK_EQ(current(), ']');
  Advance();

  if (is_negated && may_contain_strings) {
    return ReportError(RegExpError::kNegatedCharacterClassWithStrings);
  }

  if (operands->is_empty()) {
    // Return empty expression if no operands were added (e.g. [\P{Any}]
    // produces an empty range).
    DCHECK(ranges->is_empty());
    DCHECK(strings->empty());
    return RegExpClassSetExpression::Empty(zone(), is_negated);
  }

  return zone()->template New<RegExpClassSetExpression>(
      RegExpClassSetExpression::OperationType::kUnion, is_negated,
      may_contain_strings, operands);
}

// https://tc39.es/ecma262/#prod-ClassIntersection
template <class CharT>
RegExpTree* RegExpParserImpl<CharT>::ParseClassIntersection(
    const RegExpBuilder* builder, bool is_negated, RegExpTree* first_operand,
    ClassSetOperandType first_operand_type) {
  DCHECK(unicode_sets());
  DCHECK(current() == '&' && Next() == '&');
  bool may_contain_strings =
      MayContainStrings(first_operand_type, first_operand);
  ZoneList<RegExpTree*>* operands =
      zone()->template New<ZoneList<RegExpTree*>>(2, zone());
  operands->Add(first_operand, zone());
  while (has_more() && current() != ']') {
    if (current() != '&' || Next() != '&') {
      return ReportError(RegExpError::kInvalidClassSetOperation);
    }
    Advance(2);
    // [lookahead ≠ &]
    if (current() == '&') {
      return ReportError(RegExpError::kInvalidCharacterInClass);
    }

    ClassSetOperandType operand_type;
    RegExpTree* operand =
        ParseClassSetOperand(builder, &operand_type CHECK_FAILED);
    may_contain_strings &= MayContainStrings(operand_type, operand);
    operands->Add(operand, zone());
  }
  if (!has_more()) {
    return ReportError(RegExpError::kUnterminatedCharacterClass);
  }
  if (is_negated && may_contain_strings) {
    return ReportError(RegExpError::kNegatedCharacterClassWithStrings);
  }
  DCHECK_EQ(current(), ']');
  Advance();
  return zone()->template New<RegExpClassSetExpression>(
      RegExpClassSetExpression::OperationType::kIntersection, is_negated,
      may_contain_strings, operands);
}

// https://tc39.es/ecma262/#prod-ClassSubtraction
template <class CharT>
RegExpTree* RegExpParserImpl<CharT>::ParseClassSubtraction(
    const RegExpBuilder* builder, bool is_negated, RegExpTree* first_operand,
    ClassSetOperandType first_operand_type) {
  DCHECK(unicode_sets());
  DCHECK(current() == '-' && Next() == '-');
  const bool may_contain_strings =
      MayContainStrings(first_operand_type, first_operand);
  if (is_negated && may_contain_strings) {
    return ReportError(RegExpError::kNegatedCharacterClassWithStrings);
  }
  ZoneList<RegExpTree*>* operands =
      zone()->template New<ZoneList<RegExpTree*>>(2, zone());
  operands->Add(first_operand, zone());
  while (has_more() && current() != ']') {
    if (current() != '-' || Next() != '-') {
      return ReportError(RegExpError::kInvalidClassSetOperation);
    }
    Advance(2);
    ClassSetOperandType dummy;  // unused
    RegExpTree* operand = ParseClassSetOperand(builder, &dummy CHECK_FAILED);
    operands->Add(operand, zone());
  }
  if (!has_more()) {
    return ReportError(RegExpError::kUnterminatedCharacterClass);
  }
  DCHECK_EQ(current(), ']');
  Advance();
  return zone()->template New<RegExpClassSetExpression>(
      RegExpClassSetExpression::OperationType::kSubtraction, is_negated,
      may_contain_strings, operands);
}

// https://tc39.es/ecma262/#prod-CharacterClass
template <class CharT>
RegExpTree* RegExpParserImpl<CharT>::ParseCharacterClass(
    const RegExpBuilder* builder) {
  DCHECK_EQ(current(), '[');
  Advance();
  bool is_negated = false;
  if (current() == '^') {
    is_negated = true;
    Advance();
  }
  ZoneList<CharacterRange>* ranges =
      zone()->template New<ZoneList<CharacterRange>>(2, zone());
  if (current() == ']') {
    Advance();
    if (unicode_sets()) {
      return RegExpClassSetExpression::Empty(zone(), is_negated);
    } else {
      RegExpClassRanges::ClassRangesFlags class_ranges_flags;
      if (is_negated) class_ranges_flags = RegExpClassRanges::NEGATED;
      return zone()->template New<RegExpClassRanges>(zone(), ranges,
                                                     class_ranges_flags);
    }
  }

  if (!unicode_sets()) {
    bool add_unicode_case_equivalents = IsUnicodeMode() && ignore_case();
    ParseClassRanges(ranges, add_unicode_case_equivalents CHECK_FAILED);
    if (!has_more()) {
      return ReportError(RegExpError::kUnterminatedCharacterClass);
    }
    DCHECK_EQ(current(), ']');
    Advance();
    RegExpClassRanges::ClassRangesFlags character_class_flags;
    if (is_negated) character_class_flags = RegExpClassRanges::NEGATED;
    return zone()->template New<RegExpClassRanges>(zone(), ranges,
                                                   character_class_flags);
  } else {
    ClassSetOperandType operand_type;
    CharacterClassStrings* strings =
        zone()->template New<CharacterClassStrings>(zone());
    base::uc32 character;
    RegExpTree* operand = ParseClassSetOperand(
        builder, &operand_type, ranges, strings, &character CHECK_FAILED);
    switch (current()) {
      case '-':
        if (Next() == '-') {
          if (operand == nullptr) {
            if (operand_type == ClassSetOperandType::kClassSetCharacter) {
              AddMaybeSimpleCaseFoldedRange(
                  ranges, CharacterRange::Singleton(character));
            }
            operand =
                zone()->template New<RegExpClassSetOperand>(ranges, strings);
          }
          return ParseClassSubtraction(builder, is_negated, operand,
                                       operand_type);
        }
        // ClassSetRange is handled in ParseClassUnion().
        break;
      case '&':
        if (Next() == '&') {
          if (operand == nullptr) {
            if (operand_type == ClassSetOperandType::kClassSetCharacter) {
              AddMaybeSimpleCaseFoldedRange(
                  ranges, CharacterRange::Singleton(character));
            }
            operand =
                zone()->template New<RegExpClassSetOperand>(ranges, strings);
          }
          return ParseClassIntersection(builder, is_negated, operand,
                                        operand_type);
        }
    }
    return ParseClassUnion(builder, is_negated, operand, operand_type, ranges,
                           strings, character);
  }
}

#undef CHECK_FAILED

template <class CharT>
bool RegExpParserImpl<CharT>::Parse(RegExpCompileData* result) {
  DCHECK_NOT_NULL(result);
  RegExpTree* tree = ParsePattern();

  if (failed()) {
    DCHECK_NULL(tree);
    DCHECK_NE(error_, RegExpError::kNone);
    result->error = error_;
    result->error_pos = error_pos_;
    return false;
  }

  DCHECK_NOT_NULL(tree);
  DCHECK_EQ(error_, RegExpError::kNone);
  if (v8_flags.trace_regexp_parser) {
    StdoutStream os;
    tree->Print(os, zone());
    os << "\n";
  }

  result->tree = tree;
  const int capture_count = captures_started();
  result->simple = tree->IsAtom() && simple() && capture_count == 0;
  result->contains_anchor = contains_anchor();
  result->capture_count = capture_count;
  result->named_captures = GetNamedCaptures();
  return true;
}

void RegExpBuilder::FlushText() { text_builder().FlushText(); }

void RegExpBuilder::AddCharacter(base::uc16 c) {
  pending_empty_ = false;
  text_builder().AddCharacter(c);
}

void RegExpBuilder::AddUnicodeCharacter(base::uc32 c) {
  pending_empty_ = false;
  text_builder().AddUnicodeCharacter(c);
}

void RegExpBuilder::AddEscapedUnicodeCharacter(base::uc32 character) {
  pending_empty_ = false;
  text_builder().AddEscapedUnicodeCharacter(character);
}

void RegExpBuilder::AddEmpty() {
  text_builder().FlushPendingSurrogate();
  pending_empty_ = true;
}

void RegExpBuilder::AddClassRanges(RegExpClassRanges* cc) {
  pending_empty_ = false;
  text_builder().AddClassRanges(cc);
}

void RegExpBuilder::AddAtom(RegExpTree* term) {
  if (term->IsEmpty()) {
    AddEmpty();
    return;
  }
  pending_empty_ = false;
  if (term->IsTextElement()) {
    text_builder().AddAtom(term);
  } else {
    FlushText();
    terms_.emplace_back(term);
  }
}

void RegExpBuilder::AddTerm(RegExpTree* term) {
  DCHECK(!term->IsEmpty());
  pending_empty_ = false;
  if (term->IsTextElement()) {
    text_builder().AddTerm(term);
  } else {
    FlushText();
    terms_.emplace_back(term);
  }
}

void RegExpBuilder::AddAssertion(RegExpTree* assert) {
  FlushText();
  pending_empty_ = false;
  terms_.emplace_back(assert);
}

void RegExpBuilder::NewAlternative() { FlushTerms(); }

void RegExpBuilder::FlushTerms() {
  FlushText();
  size_t num_terms = terms_.size();
  RegExpTree* alternative;
  if (num_terms == 0) {
    alternative = zone()->New<RegExpEmpty>();
  } else if (num_terms == 1) {
    alternative = terms_.back();
  } else {
    alternative =
        zone()->New<RegExpAlternative>(zone()->New<ZoneList<RegExpTree*>>(
            base::VectorOf(terms_.begin(), terms_.size()), zone()));
  }
  alternatives_.emplace_back(alternative);
  terms_.clear();
}

RegExpTree* RegExpBuilder::ToRegExp() {
  FlushTerms();
  size_t num_alternatives = alternatives_.size();
  if (num_alternatives == 0) return zone()->New<RegExpEmpty>();
  if (num_alternatives == 1) return alternatives_.back();
  return zone()->New<RegExpDisjunction>(zone()->New<ZoneList<RegExpTree*>>(
      base::VectorOf(alternatives_.begin(), alternatives_.size()), zone()));
}

bool RegExpBuilder::AddQuantifierToAtom(
    int min, int max, int index,
    RegExpQuantifier::QuantifierType quantifier_type) {
  if (pending_empty_) {
    pending_empty_ = false;
    return true;
  }
  RegExpTree* atom = text_builder().PopLastAtom();
  if (atom != nullptr) {
    FlushText();
  } else if (!terms_.empty()) {
    atom = terms_.back();
    terms_.pop_back();
    if (atom->IsLookaround()) {
      // With /u or /v, lookarounds are not quantifiable.
      if (IsUnicodeMode()) return false;
      // Lookbehinds are not quantifiable.
      if (atom->AsLookaround()->type() == RegExpLookaround::LOOKBEHIND) {
        return false;
      }
    }
    if (atom->max_match() == 0) {
      // Guaranteed to only match an empty string.
      if (min == 0) {
        return true;
      }
      terms_.emplace_back(atom);
      return true;
    }
  } else {
    // Only call immediately after adding an atom or character!
    UNREACHABLE();
  }
  terms_.emplace_back(
      zone()->New<RegExpQuantifier>(min, max, quantifier_type, index, atom));
  return true;
}

template class RegExpParserImpl<uint8_t>;
template class RegExpParserImpl<base::uc16>;

}  // namespace

// static
bool RegExpParser::ParseRegExpFromHeapString(Isolate* isolate, Zone* zone,
                                             DirectHandle<String> input,
                                             RegExpFlags flags,
                                             RegExpCompileData* result) {
  DisallowGarbageCollection no_gc;
  uintptr_t stack_limit = isolate->stack_guard()->real_climit();
  String::FlatContent content = input->GetFlatContent(no_gc);
  if (content.IsOneByte()) {
    base::Vector<const uint8_t> v = content.ToOneByteVector();
    return RegExpParserImpl<uint8_t>{v.begin(),   v.length(), flags,
                                     stack_limit, zone,       no_gc}
        .Parse(result);
  } else {
    base::Vector<const base::uc16> v = content.ToUC16Vector();
    return RegExpParserImpl<base::uc16>{v.begin(),   v.length(), flags,
                                        stack_limit, zone,       no_gc}
        .Parse(result);
  }
}

// static
template <class CharT>
bool RegExpParser::VerifyRegExpSyntax(Zone* zone, uintptr_t stack_limit,
                                      const CharT* input, int input_length,
                                      RegExpFlags flags,
                                      RegExpCompileData* result,
                                      const DisallowGarbageCollection& no_gc) {
  return RegExpParserImpl<CharT>{input,       input_length, flags,
                                 stack_limit, zone,         no_gc}
      .Parse(result);
}

template bool RegExpParser::VerifyRegExpSyntax<uint8_t>(
    Zone*, uintptr_t, const uint8_t*, int, RegExpFlags, RegExpCompileData*,
    const DisallowGarbageCollection&);
template bool RegExpParser::VerifyRegExpSyntax<base::uc16>(
    Zone*, uintptr_t, const base::uc16*, int, RegExpFlags, RegExpCompileData*,
    const DisallowGarbageCollection&);

}  // namespace internal
}  // namespace v8
```