Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/regexp/regexp-parser.cc`.

Here's a breakdown of how to approach this:

1. **Identify the Core Task:** The code snippet is part of a regular expression parser. Its primary function is to process different components of a regular expression string.

2. **Analyze Code Blocks:** Go through each `case` within the `switch` statement and the logic within `ParseOpenParenthesis`. Determine what part of a regex each case handles.

3. **Recognize Key Data Structures:** Notice the usage of `RegExpGroup`, `RegExpLookaround`, `RegExpAssertion`, `RegExpClassRanges`, `RegExpClassSetOperand`, `RegExpBackReference`, and `RegExpQuantifier`. These represent the internal representation of regex elements.

4. **Infer Functionality from Actions:**  Actions like `builder->AddAtom()`, `builder->AddAssertion()`, `builder->AddClassRanges()` indicate the construction of an abstract syntax tree or similar internal representation of the regex.

5. **Connect to Regex Syntax:** Relate the code's actions back to standard regex syntax (e.g., `( ... )` for groups, `*`, `+`, `?` for quantifiers, `^`, `$` for anchors, `.` for any character, `[...]` for character classes, `\d`, `\w`, etc. for character escapes, `\1`, `\2` for backreferences, `(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)` for lookarounds).

6. **Consider Error Handling:** Note the calls to `ReportError()`, which signifies validation and error reporting during parsing.

7. **Address Specific Instructions:**
    * **`.tq` extension:** State that it's not a Torque file based on the `.cc` extension.
    * **JavaScript relationship:** Provide JavaScript regex examples that correspond to the parsed features.
    * **Logic Inference:**  Give examples of input regex snippets and how the code might process them.
    * **Common Errors:** Identify common regex syntax errors that the parser would catch.
    * **Part of a larger process:**  Emphasize that this is only a part of the complete regex compilation pipeline.

8. **Structure the Summary:** Organize the findings into a clear and concise summary covering the different aspects of the code's functionality.
这段代码是V8引擎正则表达式解析器 `RegExpParserImpl` 的一部分，负责解析正则表达式字符串中的各种结构。它主要处理正则表达式的**项 (Term)**，也就是构成正则表达式的基本单元。

以下是这段代码的主要功能归纳：

**核心功能：解析正则表达式的各项 (Terms)**

这段代码在一个大的循环中遍历正则表达式字符串的字符，并根据当前字符和后续字符的组合，构建正则表达式的抽象语法树 (AST)。它处理了多种正则表达式的构造块，包括：

* **分组 (Groups):**
    * `(...)`:  捕获型分组。代码会创建 `RegExpGroup` 对象。
    * `(?:...)`: 非捕获型分组（代码中体现为 `GROUPING` 类型）。
    * `(?=...)`:  正向先行断言 (Positive Lookahead)。创建 `RegExpLookaround` 对象。
    * `(?!...)`:  负向先行断言 (Negative Lookahead)。创建 `RegExpLookaround` 对象。
    * `(?<=...)`: 正向后行断言 (Positive Lookbehind)。创建 `RegExpLookaround` 对象。
    * `(?<!...)`: 负向后行断言 (Negative Lookbehind)。创建 `RegExpLookaround` 对象。
    * `(?<name>...)`: 命名捕获分组。代码会记录捕获组的名称。
    * `(?'name'...)`:  另一种命名捕获分组的语法。
    * `(?modifier-modifier:...)`:  修饰符分组 (例如 `(?i-m:...)`)。

* **选择 (Alternatives):**
    * `|`:  表示或的关系。代码会创建新的 `Alternative`。

* **锚点 (Anchors):**
    * `^`:  匹配输入字符串的开头（或行的开头，如果设置了 `m` 多行模式）。创建 `RegExpAssertion` 对象。
    * `$`:  匹配输入字符串的结尾（或行的结尾，如果设置了 `m` 多行模式）。创建 `RegExpAssertion` 对象。
    * `\b`:  匹配单词边界。创建 `RegExpAssertion` 对象。
    * `\B`:  匹配非单词边界。创建 `RegExpAssertion` 对象。

* **任意字符 (Any Character):**
    * `.`:  匹配除了换行符以外的任意字符（除非设置了 `s` dotall 模式，此时匹配所有字符）。创建 `RegExpClassRanges` 对象。

* **字符类 (Character Classes):**
    * `[...]`:  匹配方括号内的任意字符。调用 `ParseCharacterClass` 进行解析。

* **转义序列 (Escape Sequences):**
    * `\数字`:  反向引用捕获组。创建 `RegExpBackReference` 对象。
    * `\0`:  null 字符。
    * `\b`:  退格符。
    * `\d`, `\D`, `\s`, `\S`, `\w`, `\W`:  预定义的字符类。创建 `RegExpClassRanges` 对象。
    * `\p{...}`, `\P{...}`: Unicode 属性转义。创建 `RegExpClassSetOperand` 对象。
    * `\k<name>`:  反向引用命名捕获组。
    * `\uXXXX`, `\u{XXXXX}`: Unicode 字符。
    * `\xXX`: 十六进制字符。
    * `\cX`:  控制字符。
    * 其他转义：可能作为字面字符处理。

* **量词 (Quantifiers):**
    * `*`:  零次或多次匹配。
    * `+`:  一次或多次匹配。
    * `?`:  零次或一次匹配。
    * `{n}`:  匹配 `n` 次。
    * `{n,}`:  匹配至少 `n` 次。
    * `{n,m}`: 匹配至少 `n` 次，至多 `m` 次。
    * `*?`, `+?`, `??`, `{n}?`, `{n,}?`, `{n,m}?`:  非贪婪匹配。
    * `*+`, `++`, `?+`, `{n}+`, `{n,}+`, `{n,m}+`:  占有型匹配 (需要启用 `v8_flags.regexp_possessive_quantifier` 调试标志)。

**关于文件类型和 JavaScript 关系：**

* **`.tq` 扩展:**  如果 `v8/src/regexp/regexp-parser.cc` 以 `.tq` 结尾，那么它确实是 V8 Torque 源代码。但根据描述，它以 `.cc` 结尾，所以是 **C++ 源代码**。 Torque 是一种用于生成 V8 内部代码的领域特定语言。
* **JavaScript 关系:** 这个 C++ 代码直接负责解析 JavaScript 中使用的正则表达式。

**JavaScript 举例说明:**

```javascript
// 捕获型分组
const regex1 = /(ab)+/g;
// 非捕获型分组
const regex2 = /(?:ab)+/g;
// 正向先行断言
const regex3 = /ab(?=c)/g;
// 负向先行断言
const regex4 = /ab(?!c)/g;
// 正向后行断言
const regex5 = /(?<=a)bc/g;
// 负向后行断言
const regex6 = /(?<!a)bc/g;
// 命名捕获分组
const regex7 = /(?<name>ab)+/g;
// 选择
const regex8 = /a|b/g;
// 锚点
const regex9 = /^abc$/g;
// 任意字符
const regex10 = /a.b/g;
// 字符类
const regex11 = /[abc]/g;
// 反向引用
const regex12 = /(.)\1/g;
// Unicode 属性转义 (需要 /u 标志)
const regex13 = /\p{Emoji}/gu;
// 量词
const regex14 = /a*/g;
const regex15 = /a+/g;
const regex16 = /a?/g;
const regex17 = /a{3}/g;
const regex18 = /a{3,}/g;
const regex19 = /a{3,5}/g;
const regex20 = /a+?/g; // 非贪婪
```

**代码逻辑推理 (假设输入与输出):**

**假设输入:**  正则表达式字符串 `(a*|b)`

**解析过程 (简化):**

1. 遇到 `(`: 调用 `ParseOpenParenthesis`，创建一个新的 `RegExpParserState` 和 `RegExpBuilder`，用于处理分组内的内容。类型为 `CAPTURE`。
2. 遇到 `a`:  作为字面字符处理，`builder->AddUnicodeCharacter('a')`。
3. 遇到 `*`:  识别为量词，应用于之前的 `a`，`builder->AddQuantifierToAtom(0, RegExpTree::kInfinity, ...)`。
4. 遇到 `|`:  表示选择，`state->NewAlternative()`, `builder->NewAlternative()`。
5. 遇到 `b`:  作为字面字符处理，`builder->AddUnicodeCharacter('b')`。
6. 遇到 `)`:  分组结束，创建 `RegExpGroup` 对象，并将分组内的表达式作为其 `body`。恢复之前的状态。`builder->AddAtom(group)`。

**可能的输出 (AST 的一部分):**  可能会创建一个 `RegExpGroup` 对象，其 `body` 包含一个 `RegExpDisjunction` 对象，该 `RegExpDisjunction` 有两个 `Alternative`，分别表示 `a*` 和 `b`。

**用户常见的编程错误:**

* **括号不匹配:**  例如 `(ab` 或 `ab)`。解析器会报错，如 `RegExpError::kUnmatchedParenthesis` (虽然这段代码片段没有直接显示此错误，但在完整的解析器中会有处理)。
* **无效的转义序列:** 例如 `\q`。解析器会报错，如 `RegExpError::kInvalidEscape`。
* **量词应用于没有可重复的项:** 例如 `*`, `+`, `?` 出现在表达式的开头或者在其他需要一个原子 (atom) 的位置。代码中的 `case '*'`, `case '+'`, `case '?'` 会返回 `ReportError(RegExpError::kNothingToRepeat)`。
* **反向引用了不存在的捕获组:** 例如，只有两个捕获组，但使用了 `\3`。这段代码会检查捕获组的数量。
* **命名捕获组名称无效:**  使用了非法的字符作为命名捕获组的名称。 `ParseCaptureGroupName` 中有相关校验。
* **重复的命名捕获组名称 (取决于标志):** 如果没有启用 `v8_flags.js_regexp_duplicate_named_groups`，则不允许重复的命名捕获组。

**归纳其功能 (第 2 部分):**

这段代码主要负责解析正则表达式字符串中表示 **项 (Term)** 的部分，包括分组、选择、锚点、任意字符、字符类和转义序列。它识别这些结构，并创建相应的内部表示对象，以便后续的正则表达式编译过程能够理解和使用。 这部分代码是构建正则表达式抽象语法树的核心组成部分，负责将文本形式的正则表达式转换为结构化的数据表示。

### 提示词
```
这是目录为v8/src/regexp/regexp-parser.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/regexp-parser.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
{
          body = zone()->template New<RegExpGroup>(body, builder->flags());
        } else {
          DCHECK(group_type == POSITIVE_LOOKAROUND ||
                 group_type == NEGATIVE_LOOKAROUND);
          bool is_positive = (group_type == POSITIVE_LOOKAROUND);
          body = zone()->template New<RegExpLookaround>(
              body, is_positive, end_capture_index - capture_index,
              capture_index, state->lookaround_type(), lookaround_count_);
          lookaround_count_++;
        }

        // Restore previous state.
        state = state->previous_state();
        builder = state->builder();

        builder->AddAtom(body);
        // For compatibility with JSC and ES3, we allow quantifiers after
        // lookaheads, and break in all cases.
        break;
      }
      case '|': {
        Advance();
        state->NewAlternative(captures_started());
        builder->NewAlternative();
        continue;
      }
      case '*':
      case '+':
      case '?':
        return ReportError(RegExpError::kNothingToRepeat);
      case '^': {
        Advance();
        builder->AddAssertion(zone()->template New<RegExpAssertion>(
            builder->multiline() ? RegExpAssertion::Type::START_OF_LINE
                                 : RegExpAssertion::Type::START_OF_INPUT));
        set_contains_anchor();
        continue;
      }
      case '$': {
        Advance();
        RegExpAssertion::Type assertion_type =
            builder->multiline() ? RegExpAssertion::Type::END_OF_LINE
                                 : RegExpAssertion::Type::END_OF_INPUT;
        builder->AddAssertion(
            zone()->template New<RegExpAssertion>(assertion_type));
        continue;
      }
      case '.': {
        Advance();
        ZoneList<CharacterRange>* ranges =
            zone()->template New<ZoneList<CharacterRange>>(2, zone());

        if (builder->dotall()) {
          // Everything.
          CharacterRange::AddClassEscape(StandardCharacterSet::kEverything,
                                         ranges, false, zone());
        } else {
          // Everything except \x0A, \x0D, \u2028 and \u2029.
          CharacterRange::AddClassEscape(
              StandardCharacterSet::kNotLineTerminator, ranges, false, zone());
        }

        RegExpClassRanges* cc =
            zone()->template New<RegExpClassRanges>(zone(), ranges);
        builder->AddClassRanges(cc);
        break;
      }
      case '(': {
        state = ParseOpenParenthesis(state CHECK_FAILED);
        builder = state->builder();
        flags_ = builder->flags();
        continue;
      }
      case '[': {
        RegExpTree* cc = ParseCharacterClass(builder CHECK_FAILED);
        if (cc->IsClassRanges()) {
          builder->AddClassRanges(cc->AsClassRanges());
        } else {
          DCHECK(cc->IsClassSetExpression());
          builder->AddTerm(cc);
        }
        break;
      }
      // Atom ::
      //   \ AtomEscape
      case '\\':
        switch (Next()) {
          case kEndMarker:
            return ReportError(RegExpError::kEscapeAtEndOfPattern);
          // AtomEscape ::
          //   [+UnicodeMode] DecimalEscape
          //   [~UnicodeMode] DecimalEscape but only if the CapturingGroupNumber
          //                  of DecimalEscape is ≤ NcapturingParens
          //   CharacterEscape (some cases of this mixed in too)
          //
          // TODO(jgruber): It may make sense to disentangle all the different
          // cases and make the structure mirror the spec, e.g. for AtomEscape:
          //
          //  if (TryParseDecimalEscape(...)) return;
          //  if (TryParseCharacterClassEscape(...)) return;
          //  if (TryParseCharacterEscape(...)) return;
          //  if (TryParseGroupName(...)) return;
          case '1':
          case '2':
          case '3':
          case '4':
          case '5':
          case '6':
          case '7':
          case '8':
          case '9': {
            int index = 0;
            const bool is_backref =
                ParseBackReferenceIndex(&index CHECK_FAILED);
            if (is_backref) {
              if (state->IsInsideCaptureGroup(index)) {
                // The back reference is inside the capture group it refers to.
                // Nothing can possibly have been captured yet, so we use empty
                // instead. This ensures that, when checking a back reference,
                // the capture registers of the referenced capture are either
                // both set or both cleared.
                builder->AddEmpty();
              } else {
                RegExpCapture* capture = GetCapture(index);
                RegExpTree* atom =
                    zone()->template New<RegExpBackReference>(capture, zone());
                builder->AddAtom(atom);
              }
              break;
            }
            // With /u and /v, no identity escapes except for syntax characters
            // are allowed. Otherwise, all identity escapes are allowed.
            if (IsUnicodeMode()) {
              return ReportError(RegExpError::kInvalidEscape);
            }
            base::uc32 first_digit = Next();
            if (first_digit == '8' || first_digit == '9') {
              builder->AddCharacter(first_digit);
              Advance(2);
              break;
            }
            [[fallthrough]];
          }
          case '0': {
            Advance();
            if (IsUnicodeMode() && Next() >= '0' && Next() <= '9') {
              // Decimal escape with leading 0 are not parsed as octal.
              return ReportError(RegExpError::kInvalidDecimalEscape);
            }
            base::uc32 octal = ParseOctalLiteral();
            builder->AddCharacter(octal);
            break;
          }
          case 'b':
            Advance(2);
            builder->AddAssertion(zone()->template New<RegExpAssertion>(
                RegExpAssertion::Type::BOUNDARY));
            continue;
          case 'B':
            Advance(2);
            builder->AddAssertion(zone()->template New<RegExpAssertion>(
                RegExpAssertion::Type::NON_BOUNDARY));
            continue;
          // AtomEscape ::
          //   CharacterClassEscape
          case 'd':
          case 'D':
          case 's':
          case 'S':
          case 'w':
          case 'W': {
            base::uc32 next = Next();
            ZoneList<CharacterRange>* ranges =
                zone()->template New<ZoneList<CharacterRange>>(2, zone());
            bool add_unicode_case_equivalents =
                IsUnicodeMode() && ignore_case();
            bool parsed_character_class_escape = TryParseCharacterClassEscape(
                next, InClassEscapeState::kNotInClass, ranges, nullptr, zone(),
                add_unicode_case_equivalents CHECK_FAILED);

            if (parsed_character_class_escape) {
              RegExpClassRanges* cc =
                  zone()->template New<RegExpClassRanges>(zone(), ranges);
              builder->AddClassRanges(cc);
            } else {
              CHECK(!IsUnicodeMode());
              Advance(2);
              builder->AddCharacter(next);  // IdentityEscape.
            }
            break;
          }
          case 'p':
          case 'P': {
            base::uc32 next = Next();
            ZoneList<CharacterRange>* ranges =
                zone()->template New<ZoneList<CharacterRange>>(2, zone());
            CharacterClassStrings* strings = nullptr;
            if (unicode_sets()) {
              strings = zone()->template New<CharacterClassStrings>(zone());
            }
            bool add_unicode_case_equivalents = ignore_case();
            bool parsed_character_class_escape = TryParseCharacterClassEscape(
                next, InClassEscapeState::kNotInClass, ranges, strings, zone(),
                add_unicode_case_equivalents CHECK_FAILED);

            if (parsed_character_class_escape) {
              if (unicode_sets()) {
                RegExpClassSetOperand* op =
                    zone()->template New<RegExpClassSetOperand>(ranges,
                                                                strings);
                builder->AddTerm(op);
              } else {
                RegExpClassRanges* cc =
                    zone()->template New<RegExpClassRanges>(zone(), ranges);
                builder->AddClassRanges(cc);
              }
            } else {
              CHECK(!IsUnicodeMode());
              Advance(2);
              builder->AddCharacter(next);  // IdentityEscape.
            }
            break;
          }
          // AtomEscape ::
          //   k GroupName
          case 'k': {
            // Either an identity escape or a named back-reference.  The two
            // interpretations are mutually exclusive: '\k' is interpreted as
            // an identity escape for non-Unicode patterns without named
            // capture groups, and as the beginning of a named back-reference
            // in all other cases.
            const bool has_named_captures =
                HasNamedCaptures(InClassEscapeState::kNotInClass CHECK_FAILED);
            if (IsUnicodeMode() || has_named_captures) {
              Advance(2);
              ParseNamedBackReference(builder, state CHECK_FAILED);
              break;
            }
          }
            [[fallthrough]];
          // AtomEscape ::
          //   CharacterEscape
          default: {
            bool is_escaped_unicode_character = false;
            base::uc32 c = ParseCharacterEscape(
                InClassEscapeState::kNotInClass,
                &is_escaped_unicode_character CHECK_FAILED);
            if (is_escaped_unicode_character) {
              builder->AddEscapedUnicodeCharacter(c);
            } else {
              builder->AddCharacter(c);
            }
            break;
          }
        }
        break;
      case '{': {
        int dummy;
        bool parsed = ParseIntervalQuantifier(&dummy, &dummy CHECK_FAILED);
        if (parsed) return ReportError(RegExpError::kNothingToRepeat);
        [[fallthrough]];
      }
      case '}':
      case ']':
        if (IsUnicodeMode()) {
          return ReportError(RegExpError::kLoneQuantifierBrackets);
        }
        [[fallthrough]];
      default:
        builder->AddUnicodeCharacter(current());
        Advance();
        break;
    }  // end switch(current())

    int min;
    int max;
    switch (current()) {
      // QuantifierPrefix ::
      //   *
      //   +
      //   ?
      //   {
      case '*':
        min = 0;
        max = RegExpTree::kInfinity;
        Advance();
        break;
      case '+':
        min = 1;
        max = RegExpTree::kInfinity;
        Advance();
        break;
      case '?':
        min = 0;
        max = 1;
        Advance();
        break;
      case '{':
        if (ParseIntervalQuantifier(&min, &max)) {
          if (max < min) {
            return ReportError(RegExpError::kRangeOutOfOrder);
          }
          break;
        } else if (IsUnicodeMode()) {
          // Incomplete quantifiers are not allowed.
          return ReportError(RegExpError::kIncompleteQuantifier);
        }
        continue;
      default:
        continue;
    }
    RegExpQuantifier::QuantifierType quantifier_type = RegExpQuantifier::GREEDY;
    if (current() == '?') {
      quantifier_type = RegExpQuantifier::NON_GREEDY;
      Advance();
    } else if (v8_flags.regexp_possessive_quantifier && current() == '+') {
      // v8_flags.regexp_possessive_quantifier is a debug-only flag.
      quantifier_type = RegExpQuantifier::POSSESSIVE;
      Advance();
    }
    if (!builder->AddQuantifierToAtom(min, max, quantifier_count_,
                                      quantifier_type)) {
      return ReportError(RegExpError::kInvalidQuantifier);
    }
    ++quantifier_count_;
  }
}

template <class CharT>
RegExpParserState* RegExpParserImpl<CharT>::ParseOpenParenthesis(
    RegExpParserState* state) {
  RegExpLookaround::Type lookaround_type = state->lookaround_type();
  bool is_named_capture = false;
  const ZoneVector<base::uc16>* capture_name = nullptr;
  SubexpressionType subexpr_type = CAPTURE;
  RegExpFlags flags = state->builder()->flags();
  bool parsing_modifiers = false;
  bool modifiers_polarity = true;
  RegExpFlags modifiers;
  Advance();
  if (current() == '?') {
    do {
      switch (Next()) {
        case '-':
          if (!v8_flags.js_regexp_modifiers) {
            ReportError(RegExpError::kInvalidGroup);
            return nullptr;
          }
          Advance();
          parsing_modifiers = true;
          if (modifiers_polarity == false) {
            ReportError(RegExpError::kMultipleFlagDashes);
            return nullptr;
          }
          modifiers_polarity = false;
          break;
        case 'm':
        case 'i':
        case 's': {
          if (!v8_flags.js_regexp_modifiers) {
            ReportError(RegExpError::kInvalidGroup);
            return nullptr;
          }
          Advance();
          parsing_modifiers = true;
          RegExpFlag flag = TryRegExpFlagFromChar(current()).value();
          if ((modifiers & flag) != 0) {
            ReportError(RegExpError::kRepeatedFlag);
            return nullptr;
          }
          modifiers |= flag;
          flags.set(flag, modifiers_polarity);
          break;
        }
        case ':':
          Advance(2);
          parsing_modifiers = false;
          subexpr_type = GROUPING;
          break;
        case '=':
          Advance(2);
          if (parsing_modifiers) {
            DCHECK(v8_flags.js_regexp_modifiers);
            ReportError(RegExpError::kInvalidGroup);
            return nullptr;
          }
          lookaround_type = RegExpLookaround::LOOKAHEAD;
          subexpr_type = POSITIVE_LOOKAROUND;
          break;
        case '!':
          Advance(2);
          if (parsing_modifiers) {
            DCHECK(v8_flags.js_regexp_modifiers);
            ReportError(RegExpError::kInvalidGroup);
            return nullptr;
          }
          lookaround_type = RegExpLookaround::LOOKAHEAD;
          subexpr_type = NEGATIVE_LOOKAROUND;
          break;
        case '<':
          Advance();
          if (parsing_modifiers) {
            DCHECK(v8_flags.js_regexp_modifiers);
            ReportError(RegExpError::kInvalidGroup);
            return nullptr;
          }
          if (Next() == '=') {
            Advance(2);
            lookaround_type = RegExpLookaround::LOOKBEHIND;
            subexpr_type = POSITIVE_LOOKAROUND;
            break;
          } else if (Next() == '!') {
            Advance(2);
            lookaround_type = RegExpLookaround::LOOKBEHIND;
            subexpr_type = NEGATIVE_LOOKAROUND;
            break;
          }
          is_named_capture = true;
          has_named_captures_ = true;
          Advance();
          break;
        default:
          ReportError(RegExpError::kInvalidGroup);
          return nullptr;
      }
    } while (parsing_modifiers);
  }
  if (modifiers_polarity == false) {
    // We encountered a dash.
    if (modifiers == 0) {
      ReportError(RegExpError::kInvalidFlagGroup);
      return nullptr;
    }
  }
  if (subexpr_type == CAPTURE) {
    if (captures_started_ >= RegExpMacroAssembler::kMaxCaptures) {
      ReportError(RegExpError::kTooManyCaptures);
      return nullptr;
    }
    captures_started_++;

    if (is_named_capture) {
      capture_name = ParseCaptureGroupName(CHECK_FAILED);
    }
  }
  // Store current state and begin new disjunction parsing.
  return zone()->template New<RegExpParserState>(
      state, subexpr_type, lookaround_type, captures_started_, capture_name,
      flags, zone());
}

// In order to know whether an escape is a backreference or not we have to scan
// the entire regexp and find the number of capturing parentheses.  However we
// don't want to scan the regexp twice unless it is necessary.  This mini-parser
// is called when needed.  It can see the difference between capturing and
// noncapturing parentheses and can skip character classes and backslash-escaped
// characters.
//
// Important: The scanner has to be in a consistent state when calling
// ScanForCaptures, e.g. not in the middle of an escape sequence '\[' or while
// parsing a nested class.
template <class CharT>
void RegExpParserImpl<CharT>::ScanForCaptures(
    InClassEscapeState in_class_escape_state) {
  DCHECK(!is_scanned_for_captures_);
  const int saved_position = position();
  // Start with captures started previous to current position
  int capture_count = captures_started();
  // When we start inside a character class, skip everything inside the class.
  if (in_class_escape_state == InClassEscapeState::kInClass) {
    // \k is always invalid within a class in unicode mode, thus we should never
    // call ScanForCaptures within a class.
    DCHECK(!IsUnicodeMode());
    int c;
    while ((c = current()) != kEndMarker) {
      Advance();
      if (c == '\\') {
        Advance();
      } else {
        if (c == ']') break;
      }
    }
  }
  // Add count of captures after this position.
  int n;
  while ((n = current()) != kEndMarker) {
    Advance();
    switch (n) {
      case '\\':
        Advance();
        break;
      case '[': {
        int class_nest_level = 0;
        int c;
        while ((c = current()) != kEndMarker) {
          Advance();
          if (c == '\\') {
            Advance();
          } else if (c == '[') {
            // With /v, '[' inside a class is treated as a nested class.
            // Without /v, '[' is a normal character.
            if (unicode_sets()) class_nest_level++;
          } else if (c == ']') {
            if (class_nest_level == 0) break;
            class_nest_level--;
          }
        }
        break;
      }
      case '(':
        if (current() == '?') {
          // At this point we could be in
          // * a non-capturing group '(:',
          // * a lookbehind assertion '(?<=' '(?<!'
          // * or a named capture '(?<'.
          //
          // Of these, only named captures are capturing groups.

          Advance();
          if (current() != '<') break;

          Advance();
          if (current() == '=' || current() == '!') break;

          // Found a possible named capture. It could turn out to be a syntax
          // error (e.g. an unterminated or invalid name), but that distinction
          // does not matter for our purposes.
          has_named_captures_ = true;
        }
        capture_count++;
        break;
    }
  }
  capture_count_ = capture_count;
  is_scanned_for_captures_ = true;
  Reset(saved_position);
}

template <class CharT>
bool RegExpParserImpl<CharT>::ParseBackReferenceIndex(int* index_out) {
  DCHECK_EQ('\\', current());
  DCHECK('1' <= Next() && Next() <= '9');
  // Try to parse a decimal literal that is no greater than the total number
  // of left capturing parentheses in the input.
  int start = position();
  int value = Next() - '0';
  Advance(2);
  while (true) {
    base::uc32 c = current();
    if (IsDecimalDigit(c)) {
      value = 10 * value + (c - '0');
      if (value > RegExpMacroAssembler::kMaxCaptures) {
        Reset(start);
        return false;
      }
      Advance();
    } else {
      break;
    }
  }
  if (value > captures_started()) {
    if (!is_scanned_for_captures_) {
      ScanForCaptures(InClassEscapeState::kNotInClass);
    }
    if (value > capture_count_) {
      Reset(start);
      return false;
    }
  }
  *index_out = value;
  return true;
}

namespace {

void push_code_unit(ZoneVector<base::uc16>* v, uint32_t code_unit) {
  if (code_unit <= unibrow::Utf16::kMaxNonSurrogateCharCode) {
    v->push_back(code_unit);
  } else {
    v->push_back(unibrow::Utf16::LeadSurrogate(code_unit));
    v->push_back(unibrow::Utf16::TrailSurrogate(code_unit));
  }
}

}  // namespace

template <class CharT>
const ZoneVector<base::uc16>* RegExpParserImpl<CharT>::ParseCaptureGroupName() {
  // Due to special Advance requirements (see the next comment), rewind by one
  // such that names starting with a surrogate pair are parsed correctly for
  // patterns where the unicode flag is unset.
  //
  // Note that we use this odd pattern of rewinding the last advance in order
  // to adhere to the common parser behavior of expecting `current` to point at
  // the first candidate character for a function (e.g. when entering ParseFoo,
  // `current` should point at the first character of Foo).
  RewindByOneCodepoint();

  ZoneVector<base::uc16>* name =
      zone()->template New<ZoneVector<base::uc16>>(zone());

  {
    // Advance behavior inside this function is tricky since
    // RegExpIdentifierName explicitly enables unicode (in spec terms, sets +U)
    // and thus allows surrogate pairs and \u{}-style escapes even in
    // non-unicode patterns. Therefore Advance within the capture group name
    // has to force-enable unicode, and outside the name revert to default
    // behavior.
    ForceUnicodeScope force_unicode(this);

    bool at_start = true;
    while (true) {
      Advance();
      base::uc32 c = current();

      // Convert unicode escapes.
      if (c == '\\' && Next() == 'u') {
        Advance(2);
        if (!ParseUnicodeEscape(&c)) {
          ReportError(RegExpError::kInvalidUnicodeEscape);
          return nullptr;
        }
        RewindByOneCodepoint();
      }

      // The backslash char is misclassified as both ID_Start and ID_Continue.
      if (c == '\\') {
        ReportError(RegExpError::kInvalidCaptureGroupName);
        return nullptr;
      }

      if (at_start) {
        if (!IsIdentifierStart(c)) {
          ReportError(RegExpError::kInvalidCaptureGroupName);
          return nullptr;
        }
        push_code_unit(name, c);
        at_start = false;
      } else {
        if (c == '>') {
          break;
        } else if (IsIdentifierPart(c)) {
          push_code_unit(name, c);
        } else {
          ReportError(RegExpError::kInvalidCaptureGroupName);
          return nullptr;
        }
      }
    }
  }

  // This final advance goes back into the state of pointing at the next
  // relevant char, which the rest of the parser expects. See also the previous
  // comments in this function.
  Advance();
  return name;
}

template <class CharT>
bool RegExpParserImpl<CharT>::CreateNamedCaptureAtIndex(
    const RegExpParserState* state, int index) {
  const ZoneVector<base::uc16>* name = state->capture_name();
  const std::pair<int, int> non_participating_capture_group_interval =
      state->non_participating_capture_group_interval();
  DCHECK(0 < index && index <= captures_started_);
  DCHECK_NOT_NULL(name);

  RegExpCapture* capture = GetCapture(index);
  DCHECK_NULL(capture->name());

  capture->set_name(name);

  if (named_captures_ == nullptr) {
    named_captures_ = zone_->template New<
        ZoneMap<RegExpCapture*, ZoneList<int>*, RegExpCaptureNameLess>>(zone());
  } else {
    // Check for duplicates and bail if we find any.
    const auto& named_capture_it = named_captures_->find(capture);
    if (named_capture_it != named_captures_->end()) {
      if (v8_flags.js_regexp_duplicate_named_groups) {
        ZoneList<int>* named_capture_indices = named_capture_it->second;
        DCHECK_NOT_NULL(named_capture_indices);
        DCHECK(!named_capture_indices->is_empty());
        for (int named_index : *named_capture_indices) {
          if (named_index < non_participating_capture_group_interval.first ||
              named_index > non_participating_capture_group_interval.second) {
            ReportError(RegExpError::kDuplicateCaptureGroupName);
            return false;
          }
        }
      } else {
        ReportError(RegExpError::kDuplicateCaptureGroupName);
        return false;
      }
    }
  }

  auto entry = named_captures_->try_emplace(
      capture, zone()->template New<ZoneList<int>>(1, zone()));
  entry.first->second->Add(index, zone());
  return true;
}

template <class CharT>
bool RegExpParserImpl<CharT>::ParseNamedBackReference(
    RegExpBuilder* builder, RegExpParserState* state) {
  // The parser is assumed to be on the '<' in \k<name>.
  if (current() != '<') {
    ReportError(RegExpError::kInvalidNamedReference);
    return false;
  }

  Advance();
  const ZoneVector<base::uc16>* name = ParseCaptureGroupName();
  if (name == nullptr) {
    return false;
  }

  if (state->IsInsideCaptureGroup(name)) {
    builder->AddEmpty();
  } else {
    RegExpBackReference* atom =
        zone()->template New<RegExpBackReference>(zone());
    atom->set_name(name);

    builder->AddAtom(atom);

    if (named_back_references_ == nullptr) {
      named_back_references_ =
          zone()->template New<ZoneList<RegExpBackReference*>>(1, zone());
    }
    named_back_references_->Add(atom, zone());
  }

  return true;
}

template <class CharT>
void RegExpParserImpl<CharT>::PatchNamedBackReferences() {
  if (named_back_references_ == nullptr) return;

  if (named_captures_ == nullptr) {
    ReportError(RegExpError::kInvalidNamedCaptureReference);
    return;
  }

  // Look up and patch the actual capture for each named back reference.

  for (int i = 0; i < named_back_references_->length(); i++) {
    RegExpBackReference* ref = named_back_references_->at(i);

    // Capture used to search the named_captures_ by name, index of the
    // capture is never used.
    static const int kInvalidIndex = 0;
    RegExpCapture* search_capture =
        zone()->template New<RegExpCapture>(kInvalidIndex);
    DCHECK_NULL(search_capture->name());
    search_capture->set_name(ref->name());

    const auto& capture_it = named_captures_->find(search_capture);
    if (capture_it == named_captures_->end()) {
      ReportError(RegExpError::kInvalidNamedCaptureReference);
      return;
    }

    DCHECK_IMPLIES(!v8_flags.js_regexp_duplicate_named_groups,
                   capture_it->second->length() == 1);
    for (int index : *capture_it->second) {
      ref->add_capture(GetCapture(index), zone());
    }
  }
}

template <class CharT>
RegExpCapture* RegExpParserImpl<CharT>::GetCapture(int index) {
  // The index for the capture groups are one-based. Its index in the list is
  // zero-based.
  const int known_captures =
      is_scanned_for_captures_ ? capture_count_ : captures_started_;
  DCHECK(index <= known_captures);
  if (captures_ == nullptr) {
    captures_ =
        zone()->template New<ZoneList<RegExpCapture*>>(known_captures, zone());
  }
  while (captures_->length() < known_captures) {
    captures_->Add(zone()->template New<RegExpCapture>(captures_->length() + 1),
                   zone());
  }
  return captures_->at(index - 1);
}

template <class CharT>
ZoneVector<RegExpCapture*>* RegExpParserImpl<CharT>::GetNamedCaptures() {
  if (named_captures_ == nullptr) {
    return nullptr;
  }
  DCHECK(!named_captures_->empty());

  ZoneVector<RegExpCapture*>* flattened_named_captures =
      zone()->template New<ZoneVector<RegExpCapture*>>(zone());
  for (auto capture : *named_captures_) {
    DCHECK_IMPLIES(!v8_flags.js_regexp_duplicate_named_groups,
                   capture.second->length() == 1);
    for (int index : *capture.second) {
      flattened_named_captures->push_back(GetCapture(index));
    }
  }
  return flattened_named_captures;
}

template <class CharT>
bool RegExpParserImpl<CharT>::HasNamedCaptures(
    InClassEscapeState in_class_escape_state) {
  if (has_named_captures_ || is_scanned_for_captures_) {
    return has_named_captures_;
  }

  ScanForCaptures(in_class_escape_state);
  DCHECK(is_scanned_for_captures_);
  return has_named_captures_;
}

// QuantifierPrefix ::
//   { DecimalDigits }
//   { DecimalDigits , }
//   { DecimalDigits , DecimalDigits }
//
// Returns true if parsing succeeds, and set the min_out and max_out
// values. Values are truncated to RegExpTree::kInfinity if they overflow.
template <class CharT>
bool RegExpParserImpl<CharT>::ParseIntervalQuantifier(int* min_out,
                                                      int* max_out) {
  DCHECK_EQ(current(), '{');
  int start = position();
  Advance();
  int min = 0;
  if (!IsDecimalDigit(current())) {
    Reset(start);
    return false;
  }
  while (IsDecimalDigit(current())) {
    int next = current() - '0';
    if (min > (RegExpTree::kInfinity - next) / 10) {
      // Overflow. Skip past remaining decimal digits and return -1.
      do {
        Advance();
      } while (IsDecimalDigit(current()));
      min = RegExpTree::kInfinity;
      break;
    }
    min = 10 * min + next;
    Advance();
  }
  int max = 0;
  if (current() == '}') {
    max = min;
    Advance();
  } else if (current() == ',') {
    Advance();
    if (current() == '}') {
      max = RegExpTree::kInfinity;
      Advance();
    } else {
      while (IsDecimalDigit(current())) {
        int next = current() - '0';
        if (max > (RegExpTree::kInfinity - next) / 10) {
          do {
            Advance();
          } while (IsDecimalDigit(current()));
          max = RegExpTree::kInfinity;
          break;
        }
        max = 10 * max + next;
        Advance();
      }
      if (current() != '}') {
        Reset(start);
        return false;
      }
      Advance();
    }
  } else {
    Reset(start);
    return false;
  }
  *min_out = min;
  *max_out = max;
  return true;
}

template <class CharT>
base::uc32 RegExpParserImpl<CharT>::ParseOctalLiteral() {
  DCHECK(('0' <= current() && current() <= '7') || !has_more());
  // For compatibility with some other browsers (not all), we parse
  // up to three octal digits with a value below 256.
  // ES#prod-annexB-LegacyOctalEscapeSequence
  base::uc32 value = current() - '0';
  Advance();
  if ('0' <= current() && current() <= '7') {
    value = value * 8 + current() - '0';
    Advance();
    if (value < 32 && '0' <= current() && current() <= '7') {
      value = value * 8 + current() - '0';
      Advance();
    }
  }
  return value;
}

template <class CharT>
bool RegExpParserImpl<CharT>::ParseHexEscape(int length, base::uc32* value) {
  int start = position();
  base::uc32 val = 0;
  for (int i = 0; i < length; ++i) {
    base::uc32 c = current();
    int d = base::HexValue(c);
    if (d < 0) {
      Reset(start);
      return false;
    }
    val = val * 16 + d;
    Advance();
  }
  *value = val;
  return true;
}

// This parses RegExpUnicodeEscapeSequence as described in ECMA262.
template <class CharT>
bool RegExpParserImpl<CharT>::ParseUnicodeEscape(base::uc32* value) {
  // Accept both \uxxxx and \u{xxxxxx} (if harmony unicode escapes are
  // allowed). In the latter case, the number of hex digits between { } is
  // arbitrary. \ and u have already been read.
  if (current() == '{' && IsUnicodeMode()) {
    int start = position();
    Advance();
    if (ParseUnlimitedLengthHexNumber(0x10FFFF, value)) {
      if (current() == '}') {
        Advance();
        return true;
      }
    }
    Reset(start);
    return false;
  }
  // \u but no {, or \u{...} escapes not allowed.
  bool result = ParseHexEscape(4, value);
  if (result && IsUnicodeMode() && unibrow::Utf16::IsLeadSurrogate(*value) &&
      current() == '\\') {
    // Attempt to read trail surrogate.
    int start = position();
    if (Next() == 'u') {
      Advance(2);
      base::uc32 trail;
      if (ParseHexEscape(4, &trail) &&
          unibrow::Utf16::IsTrailSurrogate(trail)) {
        *value = unibrow::Utf16::CombineSurrogatePair(
            static_cast<base::uc16>(*value), static_cast<base::uc16>(trail));
        return true;
      }
    }
    Reset(start);
  }
  return result;
}

#ifdef V8_INTL_SUPPORT

namespace {

bool IsExactPropertyAlias(const char* property_name, UProperty property) {
  const char* short_name = u_getPropertyName(property, U_SHORT_PROPERTY_NAME);
  if (short_name != nullptr && strcmp(property_name, short_name) == 0)
    return true;
  for (int i = 0;; i++) {
    const char* long_name = u_getPropertyName(
        property, static_cast<UPropertyNameChoice>(U_LONG_PROPERTY_NAME + i));
    if (long_name == nullptr) break;
    if (strcmp(property_name, long_name) == 0) return true;
  }
  return false;
}

bool IsExactPropertyValueAlias(const char* property_value_name,
                               UProperty property, int32_t property_value) {
  const char* short_name =
      u_getPropertyValueName(property, property_value, U_SHORT_PROPERTY_NAME);
  if (short_name != nullptr && strcmp(property_value_name, short_name) == 0) {
    return true;
  }
  for (int i = 0;; i++) {
    const char* long_name = u_getPropertyValueName(
        property, property_value,
        static_cast<UPropertyNameChoice>(U_LONG_PROPERTY_NAME + i));
    if (long_name == nullptr) break;
    if (strcmp(
```