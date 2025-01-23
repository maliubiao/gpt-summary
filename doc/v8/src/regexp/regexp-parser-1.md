Response: The user wants to understand the functionality of the C++ code snippet from `v8/src/regexp/regexp-parser.cc`. This is the second part of the file. The request also asks to illustrate its relationship with JavaScript using examples if applicable.

**Plan:**

1. **Analyze the provided code:** Focus on the functions, classes, and logic implemented in this part of the file. Identify the core responsibilities.
2. **Connect to JavaScript RegExp:** Based on the identified functionalities, determine how they relate to JavaScript's regular expression capabilities.
3. **Provide JavaScript examples:** Illustrate the connection with specific JavaScript RegExp features and syntax.
这个C++代码片段是V8引擎正则表达式解析器的一部分，主要负责处理正则表达式中与 Unicode 属性相关的特性，尤其是在 `/u` (Unicode) 和 `/v` (Unicode sets) 模式下的行为。

**主要功能归纳：**

1. **Unicode 属性值查找和处理：**
   - `LookupPropertyValueName`:  根据 Unicode 属性名（例如 `Script`，`General_Category`）和属性值名（例如 `Latin`，`Letter`），在 ICU (International Components for Unicode) 库中查找匹配的 Unicode 字符集。
   - `ExtractStringsFromUnicodeSet`: 从 ICU 的 `UnicodeSet` 中提取字符串，并将其存储到 `CharacterClassStrings` 中。这主要用于处理包含字符串的 Unicode 属性。
   - `IsExactPropertyValueAlias`: 验证提供的属性值名是否是 ICU 中该属性的精确别名。

2. **特殊属性值处理：**
   - `LookupSpecialPropertyValueName`:  处理一些特殊的、ICU 本身不支持的属性值，例如 "Any" (匹配所有字符), "ASCII" (匹配 ASCII 字符) 和 "Assigned" (匹配已分配的字符)。

3. **支持的 Unicode 二进制属性检查：**
   - `IsSupportedBinaryProperty`:  检查给定的 Unicode 二进制属性是否是被规范明确允许支持的，以确保跨引擎的互操作性。
   - `IsBinaryPropertyOfStrings`: 检查某个二进制属性是否可能包含字符串值。

4. **Unicode 属性值的字符验证：**
   - `IsUnicodePropertyValueCharacter`: 验证在解析 Unicode 属性名或值名时遇到的字符是否合法。

5. **解析 Unicode 属性类名：**
   - `ParsePropertyClassName`: 解析正则表达式中 `\p{...}` 或 `\P{...}` 结构内的属性名和可选的属性值名。

6. **添加 Unicode 属性类到字符范围：**
   - `AddPropertyClassRange`:  将解析到的 Unicode 属性类（包括正向和反向匹配）转换为字符范围 (`CharacterRange`) 和字符串集合 (`CharacterClassStrings`)。

7. **解析和处理不同类型的字符转义：**
   - `ParseCharacterEscape`: 解析各种字符转义序列，包括控制字符、十六进制、Unicode 转义等。在 `/u` 和 `/v` 模式下，对无效转义的处理方式与传统模式不同。
   - `ParseHexEscape`: 解析形如 `\xNN` 的十六进制转义。
   - `ParseUnicodeEscape`: 解析形如 `\uNNNN` 或 `\u{NNNNN}` 的 Unicode 转义。
   - `ParseOctalLiteral`: 解析遗留的八进制转义。

8. **解析字符类 (`[...]`) 的内容：**
   - `ParseClassRanges`: 解析字符类中的字符范围，例如 `a-z`。
   - `ParseClassEscape`: 解析字符类中的转义字符，包括 `\b`, `\d`, `\s`, `\w` 和 Unicode 属性转义 `\p{}`。
   - `TryParseCharacterClassEscape`: 尝试解析字符类转义。

9. **解析 Unicode 集（在 `/v` 模式下）：**
   - `ParseClassStringDisjunction`: 解析形如 `\q{...}` 的字符串析取。
   - `ParseClassSetOperand`: 解析 Unicode 集运算的操作数。
   - `ParseClassSetCharacter`: 解析 Unicode 集中的单个字符。
   - `ParseClassUnion`: 解析 Unicode 集的并集运算。
   - `ParseClassIntersection`: 解析 Unicode 集的交集运算。
   - `ParseClassSubtraction`: 解析 Unicode 集的差集运算。
   - `ParseCharacterClass`: 解析整个字符类，包括对 `/v` 模式下集合运算的支持。
   - `AddMaybeSimpleCaseFoldedRange`: 在 `/v` 模式且忽略大小写时，添加字符的简单大小写折叠等价字符到字符范围。

10. **构建正则表达式树：**
    - `RegExpBuilder`: 提供了一系列方法用于构建正则表达式的抽象语法树 (AST)。

**与 JavaScript 功能的关系以及 JavaScript 示例：**

这个代码片段的核心功能是解析和处理 JavaScript 正则表达式中与 Unicode 相关的语法，尤其是在引入 Unicode 模式 (`/u` 标志) 和 Unicode 集 (`/v` 标志) 之后。

**JavaScript 示例：**

1. **Unicode 属性转义 (`\p{}` 和 `\P{}`)：**

   ```javascript
   // 匹配任何属于 Latin 脚本的字符 (需要 /u 标志)
   const regexLatin = /\p{Script=Latin}/u;
   console.log(regexLatin.test("a")); // true
   console.log(regexLatin.test("你好")); // false

   // 匹配任何不是数字的字符 (需要 /u 标志)
   const regexNotDigit = /\P{Number}/u;
   console.log(regexNotDigit.test("a")); // true
   console.log(regexNotDigit.test("1")); // false
   ```
   `LookupPropertyValueName`, `ParsePropertyClassName`, 和 `AddPropertyClassRange` 等函数负责解析和处理这些模式。

2. **Unicode 模式下更严格的转义规则：**

   ```javascript
   // 在非 Unicode 模式下，\就被当作反斜杠
   const regexNonUnicode = /\\/;
   console.log(regexNonUnicode.test("\\")); // true

   // 在 Unicode 模式下，无效的转义会报错
   try {
       const regexUnicodeInvalidEscape = /\k/u; // \k 不是有效的 Unicode 转义
   } catch (e) {
       console.error(e); // SyntaxError: Invalid escape
   }
   ```
   `ParseCharacterEscape` 函数在 `/u` 模式下执行更严格的转义规则。

3. **Unicode 集 (`/v` 标志) 的字符类运算：**

   ```javascript
   // 匹配拉丁字母或数字 (Unicode 集并集)
   const regexUnion = /[\p{Script=Latin} \p{Number}]/v;
   console.log(regexUnion.test("a")); // true
   console.log(regexUnion.test("1")); // true
   console.log(regexUnion.test("!")); // false

   // 匹配既是字母又是大写字母 (Unicode 集交集)
   const regexIntersection = /[\p{Letter} & \p{Uppercase}]/v;
   console.log(regexIntersection.test("A")); // true
   console.log(regexIntersection.test("a")); // false
   console.log(regexIntersection.test("1")); // false

   // 匹配数字但不是十进制数字 (Unicode 集差集)
   const regexSubtraction = /[\p{Number} -- \p{Decimal_Number}]/v;
   // (示例可能需要查找具体的非十进制数字类型的 Unicode 字符)
   ```
   `ParseCharacterClass`, `ParseClassUnion`, `ParseClassIntersection`, 和 `ParseClassSubtraction` 等函数负责解析和处理 `/v` 模式下的字符类运算。

4. **Unicode 集的字符串析取 (`\q{}`)：**

   ```javascript
   // 匹配 "foo" 或 "bar" (需要 /v 标志)
   const regexStringDisjunction = /[ \q{foo | bar} ]/v;
   console.log(regexStringDisjunction.test("f")); // false
   console.log(regexStringDisjunction.test("o")); // false
   console.log(regexStringDisjunction.test("b")); // false
   console.log(regexStringDisjunction.test("a")); // false
   console.log(regexStringDisjunction.test("r")); // false
   console.log(regexStringDisjunction.test(" ")); // true
   console.log(regexStringDisjunction.test("foo")); // true
   console.log(regexStringDisjunction.test("bar")); // true
   ```
   `ParseClassStringDisjunction` 函数负责解析 `\q{}` 结构。

总而言之，这个代码片段是 V8 引擎实现 JavaScript 正则表达式中高级 Unicode 特性的关键部分，确保了 JavaScript 开发者能够利用最新的 Unicode 标准进行更精确和强大的文本匹配。

### 提示词
```
这是目录为v8/src/regexp/regexp-parser.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
property_value_name, long_name) == 0) return true;
  }
  return false;
}

void ExtractStringsFromUnicodeSet(const icu::UnicodeSet& set,
                                  CharacterClassStrings* strings,
                                  RegExpFlags flags, Zone* zone) {
  DCHECK(set.hasStrings());
  DCHECK(IsUnicodeSets(flags));
  DCHECK_NOT_NULL(strings);

  RegExpTextBuilder::SmallRegExpTreeVector string_storage(zone);
  RegExpTextBuilder string_builder(zone, &string_storage, flags);
  const bool needs_case_folding = IsIgnoreCase(flags);
  icu::UnicodeSetIterator iter(set);
  iter.skipToStrings();
  while (iter.next()) {
    const icu::UnicodeString& s = iter.getString();
    const char16_t* p = s.getBuffer();
    int32_t length = s.length();
    ZoneList<base::uc32>* string =
        zone->template New<ZoneList<base::uc32>>(length, zone);
    for (int32_t i = 0; i < length;) {
      UChar32 c;
      U16_NEXT(p, i, length, c);
      string_builder.AddUnicodeCharacter(c);
      if (needs_case_folding) {
        c = u_foldCase(c, U_FOLD_CASE_DEFAULT);
      }
      string->Add(c, zone);
    }
    strings->emplace(string->ToVector(), string_builder.ToRegExp());
    string_storage.clear();
  }
}

bool LookupPropertyValueName(UProperty property,
                             const char* property_value_name, bool negate,
                             ZoneList<CharacterRange>* result_ranges,
                             CharacterClassStrings* result_strings,
                             RegExpFlags flags, Zone* zone) {
  UProperty property_for_lookup = property;
  if (property_for_lookup == UCHAR_SCRIPT_EXTENSIONS) {
    // For the property Script_Extensions, we have to do the property value
    // name lookup as if the property is Script.
    property_for_lookup = UCHAR_SCRIPT;
  }
  int32_t property_value =
      u_getPropertyValueEnum(property_for_lookup, property_value_name);
  if (property_value == UCHAR_INVALID_CODE) return false;

  // We require the property name to match exactly to one of the property value
  // aliases. However, u_getPropertyValueEnum uses loose matching.
  if (!IsExactPropertyValueAlias(property_value_name, property_for_lookup,
                                 property_value)) {
    return false;
  }

  UErrorCode ec = U_ZERO_ERROR;
  icu::UnicodeSet set;
  set.applyIntPropertyValue(property, property_value, ec);
  bool success = ec == U_ZERO_ERROR && !set.isEmpty();

  if (success) {
    if (set.hasStrings()) {
      ExtractStringsFromUnicodeSet(set, result_strings, flags, zone);
    }
    const bool needs_case_folding = IsUnicodeSets(flags) && IsIgnoreCase(flags);
    if (needs_case_folding) set.closeOver(USET_SIMPLE_CASE_INSENSITIVE);
    set.removeAllStrings();
    if (negate) set.complement();
    for (int i = 0; i < set.getRangeCount(); i++) {
      result_ranges->Add(
          CharacterRange::Range(set.getRangeStart(i), set.getRangeEnd(i)),
          zone);
    }
  }
  return success;
}

template <size_t N>
inline bool NameEquals(const char* name, const char (&literal)[N]) {
  return strncmp(name, literal, N + 1) == 0;
}

bool LookupSpecialPropertyValueName(const char* name,
                                    ZoneList<CharacterRange>* result,
                                    bool negate, RegExpFlags flags,
                                    Zone* zone) {
  if (NameEquals(name, "Any")) {
    if (negate) {
      // Leave the list of character ranges empty, since the negation of 'Any'
      // is the empty set.
    } else {
      result->Add(CharacterRange::Everything(), zone);
    }
  } else if (NameEquals(name, "ASCII")) {
    result->Add(negate ? CharacterRange::Range(0x80, String::kMaxCodePoint)
                       : CharacterRange::Range(0x0, 0x7F),
                zone);
  } else if (NameEquals(name, "Assigned")) {
    return LookupPropertyValueName(UCHAR_GENERAL_CATEGORY, "Unassigned",
                                   !negate, result, nullptr, flags, zone);
  } else {
    return false;
  }
  return true;
}

// Explicitly allowlist supported binary properties. The spec forbids supporting
// properties outside of this set to ensure interoperability.
bool IsSupportedBinaryProperty(UProperty property, bool unicode_sets) {
  switch (property) {
    case UCHAR_ALPHABETIC:
    // 'Any' is not supported by ICU. See LookupSpecialPropertyValueName.
    // 'ASCII' is not supported by ICU. See LookupSpecialPropertyValueName.
    case UCHAR_ASCII_HEX_DIGIT:
    // 'Assigned' is not supported by ICU. See LookupSpecialPropertyValueName.
    case UCHAR_BIDI_CONTROL:
    case UCHAR_BIDI_MIRRORED:
    case UCHAR_CASE_IGNORABLE:
    case UCHAR_CASED:
    case UCHAR_CHANGES_WHEN_CASEFOLDED:
    case UCHAR_CHANGES_WHEN_CASEMAPPED:
    case UCHAR_CHANGES_WHEN_LOWERCASED:
    case UCHAR_CHANGES_WHEN_NFKC_CASEFOLDED:
    case UCHAR_CHANGES_WHEN_TITLECASED:
    case UCHAR_CHANGES_WHEN_UPPERCASED:
    case UCHAR_DASH:
    case UCHAR_DEFAULT_IGNORABLE_CODE_POINT:
    case UCHAR_DEPRECATED:
    case UCHAR_DIACRITIC:
    case UCHAR_EMOJI:
    case UCHAR_EMOJI_COMPONENT:
    case UCHAR_EMOJI_MODIFIER_BASE:
    case UCHAR_EMOJI_MODIFIER:
    case UCHAR_EMOJI_PRESENTATION:
    case UCHAR_EXTENDED_PICTOGRAPHIC:
    case UCHAR_EXTENDER:
    case UCHAR_GRAPHEME_BASE:
    case UCHAR_GRAPHEME_EXTEND:
    case UCHAR_HEX_DIGIT:
    case UCHAR_ID_CONTINUE:
    case UCHAR_ID_START:
    case UCHAR_IDEOGRAPHIC:
    case UCHAR_IDS_BINARY_OPERATOR:
    case UCHAR_IDS_TRINARY_OPERATOR:
    case UCHAR_JOIN_CONTROL:
    case UCHAR_LOGICAL_ORDER_EXCEPTION:
    case UCHAR_LOWERCASE:
    case UCHAR_MATH:
    case UCHAR_NONCHARACTER_CODE_POINT:
    case UCHAR_PATTERN_SYNTAX:
    case UCHAR_PATTERN_WHITE_SPACE:
    case UCHAR_QUOTATION_MARK:
    case UCHAR_RADICAL:
    case UCHAR_REGIONAL_INDICATOR:
    case UCHAR_S_TERM:
    case UCHAR_SOFT_DOTTED:
    case UCHAR_TERMINAL_PUNCTUATION:
    case UCHAR_UNIFIED_IDEOGRAPH:
    case UCHAR_UPPERCASE:
    case UCHAR_VARIATION_SELECTOR:
    case UCHAR_WHITE_SPACE:
    case UCHAR_XID_CONTINUE:
    case UCHAR_XID_START:
      return true;
    case UCHAR_BASIC_EMOJI:
    case UCHAR_EMOJI_KEYCAP_SEQUENCE:
    case UCHAR_RGI_EMOJI_MODIFIER_SEQUENCE:
    case UCHAR_RGI_EMOJI_FLAG_SEQUENCE:
    case UCHAR_RGI_EMOJI_TAG_SEQUENCE:
    case UCHAR_RGI_EMOJI_ZWJ_SEQUENCE:
    case UCHAR_RGI_EMOJI:
      return unicode_sets;
    default:
      break;
  }
  return false;
}

bool IsBinaryPropertyOfStrings(UProperty property) {
  switch (property) {
    case UCHAR_BASIC_EMOJI:
    case UCHAR_EMOJI_KEYCAP_SEQUENCE:
    case UCHAR_RGI_EMOJI_MODIFIER_SEQUENCE:
    case UCHAR_RGI_EMOJI_FLAG_SEQUENCE:
    case UCHAR_RGI_EMOJI_TAG_SEQUENCE:
    case UCHAR_RGI_EMOJI_ZWJ_SEQUENCE:
    case UCHAR_RGI_EMOJI:
      return true;
    default:
      break;
  }
  return false;
}

bool IsUnicodePropertyValueCharacter(char c) {
  // https://tc39.github.io/proposal-regexp-unicode-property-escapes/
  //
  // Note that using this to validate each parsed char is quite conservative.
  // A possible alternative solution would be to only ensure the parsed
  // property name/value candidate string does not contain '\0' characters and
  // let ICU lookups trigger the final failure.
  if ('a' <= c && c <= 'z') return true;
  if ('A' <= c && c <= 'Z') return true;
  if ('0' <= c && c <= '9') return true;
  return (c == '_');
}

}  // namespace

template <class CharT>
bool RegExpParserImpl<CharT>::ParsePropertyClassName(ZoneVector<char>* name_1,
                                                     ZoneVector<char>* name_2) {
  DCHECK(name_1->empty());
  DCHECK(name_2->empty());
  // Parse the property class as follows:
  // - In \p{name}, 'name' is interpreted
  //   - either as a general category property value name.
  //   - or as a binary property name.
  // - In \p{name=value}, 'name' is interpreted as an enumerated property name,
  //   and 'value' is interpreted as one of the available property value names.
  // - Aliases in PropertyAlias.txt and PropertyValueAlias.txt can be used.
  // - Loose matching is not applied.
  if (current() == '{') {
    // Parse \p{[PropertyName=]PropertyNameValue}
    for (Advance(); current() != '}' && current() != '='; Advance()) {
      if (!IsUnicodePropertyValueCharacter(current())) return false;
      if (!has_next()) return false;
      name_1->push_back(static_cast<char>(current()));
    }
    if (current() == '=') {
      for (Advance(); current() != '}'; Advance()) {
        if (!IsUnicodePropertyValueCharacter(current())) return false;
        if (!has_next()) return false;
        name_2->push_back(static_cast<char>(current()));
      }
      name_2->push_back(0);  // null-terminate string.
    }
  } else {
    return false;
  }
  Advance();
  name_1->push_back(0);  // null-terminate string.

  DCHECK(name_1->size() - 1 == std::strlen(name_1->data()));
  DCHECK(name_2->empty() || name_2->size() - 1 == std::strlen(name_2->data()));
  return true;
}

template <class CharT>
bool RegExpParserImpl<CharT>::AddPropertyClassRange(
    ZoneList<CharacterRange>* add_to_ranges,
    CharacterClassStrings* add_to_strings, bool negate,
    const ZoneVector<char>& name_1, const ZoneVector<char>& name_2) {
  if (name_2.empty()) {
    // First attempt to interpret as general category property value name.
    const char* name = name_1.data();
    if (LookupPropertyValueName(UCHAR_GENERAL_CATEGORY_MASK, name, negate,
                                add_to_ranges, add_to_strings, flags(),
                                zone())) {
      return true;
    }
    // Interpret "Any", "ASCII", and "Assigned".
    if (LookupSpecialPropertyValueName(name, add_to_ranges, negate, flags(),
                                       zone())) {
      return true;
    }
    // Then attempt to interpret as binary property name with value name 'Y'.
    UProperty property = u_getPropertyEnum(name);
    if (!IsSupportedBinaryProperty(property, unicode_sets())) return false;
    if (!IsExactPropertyAlias(name, property)) return false;
    // Negation of properties with strings is not allowed.
    // See
    // https://tc39.es/ecma262/#sec-static-semantics-maycontainstrings
    if (negate && IsBinaryPropertyOfStrings(property)) return false;
    if (unicode_sets()) {
      // In /v mode we can't simple lookup the "false" binary property values,
      // as the spec requires us to perform case folding before calculating the
      // complement.
      // See https://tc39.es/ecma262/#sec-compiletocharset
      // UnicodePropertyValueExpression :: LoneUnicodePropertyNameOrValue
      return LookupPropertyValueName(property, "Y", negate, add_to_ranges,
                                     add_to_strings, flags(), zone());
    } else {
      return LookupPropertyValueName(property, negate ? "N" : "Y", false,
                                     add_to_ranges, add_to_strings, flags(),
                                     zone());
    }
  } else {
    // Both property name and value name are specified. Attempt to interpret
    // the property name as enumerated property.
    const char* property_name = name_1.data();
    const char* value_name = name_2.data();
    UProperty property = u_getPropertyEnum(property_name);
    if (!IsExactPropertyAlias(property_name, property)) return false;
    if (property == UCHAR_GENERAL_CATEGORY) {
      // We want to allow aggregate value names such as "Letter".
      property = UCHAR_GENERAL_CATEGORY_MASK;
    } else if (property != UCHAR_SCRIPT &&
               property != UCHAR_SCRIPT_EXTENSIONS) {
      return false;
    }
    return LookupPropertyValueName(property, value_name, negate, add_to_ranges,
                                   add_to_strings, flags(), zone());
  }
}

#else  // V8_INTL_SUPPORT

template <class CharT>
bool RegExpParserImpl<CharT>::ParsePropertyClassName(ZoneVector<char>* name_1,
                                                     ZoneVector<char>* name_2) {
  return false;
}

template <class CharT>
bool RegExpParserImpl<CharT>::AddPropertyClassRange(
    ZoneList<CharacterRange>* add_to_ranges,
    CharacterClassStrings* add_to_strings, bool negate,
    const ZoneVector<char>& name_1, const ZoneVector<char>& name_2) {
  return false;
}

#endif  // V8_INTL_SUPPORT

template <class CharT>
bool RegExpParserImpl<CharT>::ParseUnlimitedLengthHexNumber(int max_value,
                                                            base::uc32* value) {
  base::uc32 x = 0;
  int d = base::HexValue(current());
  if (d < 0) {
    return false;
  }
  while (d >= 0) {
    x = x * 16 + d;
    if (x > static_cast<base::uc32>(max_value)) {
      return false;
    }
    Advance();
    d = base::HexValue(current());
  }
  *value = x;
  return true;
}

// https://tc39.es/ecma262/#prod-CharacterEscape
template <class CharT>
base::uc32 RegExpParserImpl<CharT>::ParseCharacterEscape(
    InClassEscapeState in_class_escape_state,
    bool* is_escaped_unicode_character) {
  DCHECK_EQ('\\', current());
  DCHECK(has_next());

  Advance();

  const base::uc32 c = current();
  switch (c) {
    // CharacterEscape ::
    //   ControlEscape :: one of
    //     f n r t v
    case 'f':
      Advance();
      return '\f';
    case 'n':
      Advance();
      return '\n';
    case 'r':
      Advance();
      return '\r';
    case 't':
      Advance();
      return '\t';
    case 'v':
      Advance();
      return '\v';
    // CharacterEscape ::
    //   c ControlLetter
    case 'c': {
      base::uc32 controlLetter = Next();
      base::uc32 letter = controlLetter & ~('A' ^ 'a');
      if (letter >= 'A' && letter <= 'Z') {
        Advance(2);
        // Control letters mapped to ASCII control characters in the range
        // 0x00-0x1F.
        return controlLetter & 0x1F;
      }
      if (IsUnicodeMode()) {
        // With /u and /v, invalid escapes are not treated as identity escapes.
        ReportError(RegExpError::kInvalidUnicodeEscape);
        return 0;
      }
      if (in_class_escape_state == InClassEscapeState::kInClass) {
        // Inside a character class, we also accept digits and underscore as
        // control characters, unless with /u or /v. See Annex B:
        // ES#prod-annexB-ClassControlLetter
        if ((controlLetter >= '0' && controlLetter <= '9') ||
            controlLetter == '_') {
          Advance(2);
          return controlLetter & 0x1F;
        }
      }
      // We match JSC in reading the backslash as a literal
      // character instead of as starting an escape.
      return '\\';
    }
    // CharacterEscape ::
    //   0 [lookahead ∉ DecimalDigit]
    //   [~UnicodeMode] LegacyOctalEscapeSequence
    case '0':
      // \0 is interpreted as NUL if not followed by another digit.
      if (Next() < '0' || Next() > '9') {
        Advance();
        return 0;
      }
      [[fallthrough]];
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
      // For compatibility, we interpret a decimal escape that isn't
      // a back reference (and therefore either \0 or not valid according
      // to the specification) as a 1..3 digit octal character code.
      // ES#prod-annexB-LegacyOctalEscapeSequence
      if (IsUnicodeMode()) {
        // With /u or /v, decimal escape is not interpreted as octal character
        // code.
        ReportError(RegExpError::kInvalidDecimalEscape);
        return 0;
      }
      return ParseOctalLiteral();
    // CharacterEscape ::
    //   HexEscapeSequence
    case 'x': {
      Advance();
      base::uc32 value;
      if (ParseHexEscape(2, &value)) return value;
      if (IsUnicodeMode()) {
        // With /u or /v, invalid escapes are not treated as identity escapes.
        ReportError(RegExpError::kInvalidEscape);
        return 0;
      }
      // If \x is not followed by a two-digit hexadecimal, treat it
      // as an identity escape.
      return 'x';
    }
    // CharacterEscape ::
    //   RegExpUnicodeEscapeSequence [?UnicodeMode]
    case 'u': {
      Advance();
      base::uc32 value;
      if (ParseUnicodeEscape(&value)) {
        *is_escaped_unicode_character = true;
        return value;
      }
      if (IsUnicodeMode()) {
        // With /u or /v, invalid escapes are not treated as identity escapes.
        ReportError(RegExpError::kInvalidUnicodeEscape);
        return 0;
      }
      // If \u is not followed by a two-digit hexadecimal, treat it
      // as an identity escape.
      return 'u';
    }
    default:
      break;
  }

  // CharacterEscape ::
  //   IdentityEscape[?UnicodeMode, ?N]
  //
  // * With /u, no identity escapes except for syntax characters are
  //   allowed.
  // * With /v, no identity escapes except for syntax characters and
  //   ClassSetReservedPunctuators (if within a class) are allowed.
  // * Without /u or /v:
  //   * '\c' is not an IdentityEscape.
  //   * '\k' is not an IdentityEscape when named captures exist.
  //   * Otherwise, all identity escapes are allowed.
  if (unicode_sets() && in_class_escape_state == InClassEscapeState::kInClass) {
    if (IsClassSetReservedPunctuator(c)) {
      Advance();
      return c;
    }
  }
  if (IsUnicodeMode()) {
    if (!IsSyntaxCharacterOrSlash(c)) {
      ReportError(RegExpError::kInvalidEscape);
      return 0;
    }
    Advance();
    return c;
  }
  DCHECK(!IsUnicodeMode());
  if (c == 'c') {
    ReportError(RegExpError::kInvalidEscape);
    return 0;
  }
  Advance();
  // Note: It's important to Advance before the HasNamedCaptures call s.t. we
  // don't start scanning in the middle of an escape.
  if (c == 'k' && HasNamedCaptures(in_class_escape_state)) {
    ReportError(RegExpError::kInvalidEscape);
    return 0;
  }
  return c;
}

// https://tc39.es/ecma262/#prod-ClassRanges
template <class CharT>
RegExpTree* RegExpParserImpl<CharT>::ParseClassRanges(
    ZoneList<CharacterRange>* ranges, bool add_unicode_case_equivalents) {
  base::uc32 char_1, char_2;
  bool is_class_1, is_class_2;
  while (has_more() && current() != ']') {
    ParseClassEscape(ranges, zone(), add_unicode_case_equivalents, &char_1,
                     &is_class_1 CHECK_FAILED);
    // ClassAtom
    if (current() == '-') {
      Advance();
      if (!has_more()) {
        // If we reach the end we break out of the loop and let the
        // following code report an error.
        break;
      } else if (current() == ']') {
        if (!is_class_1) ranges->Add(CharacterRange::Singleton(char_1), zone());
        ranges->Add(CharacterRange::Singleton('-'), zone());
        break;
      }
      ParseClassEscape(ranges, zone(), add_unicode_case_equivalents, &char_2,
                       &is_class_2 CHECK_FAILED);
      if (is_class_1 || is_class_2) {
        // Either end is an escaped character class. Treat the '-' verbatim.
        if (IsUnicodeMode()) {
          // ES2015 21.2.2.15.1 step 1.
          return ReportError(RegExpError::kInvalidCharacterClass);
        }
        if (!is_class_1) ranges->Add(CharacterRange::Singleton(char_1), zone());
        ranges->Add(CharacterRange::Singleton('-'), zone());
        if (!is_class_2) ranges->Add(CharacterRange::Singleton(char_2), zone());
        continue;
      }
      // ES2015 21.2.2.15.1 step 6.
      if (char_1 > char_2) {
        return ReportError(RegExpError::kOutOfOrderCharacterClass);
      }
      ranges->Add(CharacterRange::Range(char_1, char_2), zone());
    } else {
      if (!is_class_1) ranges->Add(CharacterRange::Singleton(char_1), zone());
    }
  }
  return nullptr;
}

// https://tc39.es/ecma262/#prod-ClassEscape
template <class CharT>
void RegExpParserImpl<CharT>::ParseClassEscape(
    ZoneList<CharacterRange>* ranges, Zone* zone,
    bool add_unicode_case_equivalents, base::uc32* char_out,
    bool* is_class_escape) {
  *is_class_escape = false;

  if (current() != '\\') {
    // Not a ClassEscape.
    *char_out = current();
    Advance();
    return;
  }

  const base::uc32 next = Next();
  switch (next) {
    case 'b':
      *char_out = '\b';
      Advance(2);
      return;
    case '-':
      if (IsUnicodeMode()) {
        *char_out = next;
        Advance(2);
        return;
      }
      break;
    case kEndMarker:
      ReportError(RegExpError::kEscapeAtEndOfPattern);
      return;
    default:
      break;
  }

  static constexpr InClassEscapeState kInClassEscape =
      InClassEscapeState::kInClass;
  *is_class_escape =
      TryParseCharacterClassEscape(next, kInClassEscape, ranges, nullptr, zone,
                                   add_unicode_case_equivalents);
  if (*is_class_escape) return;

  bool dummy = false;  // Unused.
  *char_out = ParseCharacterEscape(kInClassEscape, &dummy);
}

// https://tc39.es/ecma262/#prod-CharacterClassEscape
template <class CharT>
bool RegExpParserImpl<CharT>::TryParseCharacterClassEscape(
    base::uc32 next, InClassEscapeState in_class_escape_state,
    ZoneList<CharacterRange>* ranges, CharacterClassStrings* strings,
    Zone* zone, bool add_unicode_case_equivalents) {
  DCHECK_EQ(current(), '\\');
  DCHECK_EQ(Next(), next);

  switch (next) {
    case 'd':
    case 'D':
    case 's':
    case 'S':
    case 'w':
    case 'W':
      CharacterRange::AddClassEscape(static_cast<StandardCharacterSet>(next),
                                     ranges, add_unicode_case_equivalents,
                                     zone);
      Advance(2);
      return true;
    case 'p':
    case 'P': {
      if (!IsUnicodeMode()) return false;
      bool negate = next == 'P';
      Advance(2);
      ZoneVector<char> name_1(zone);
      ZoneVector<char> name_2(zone);
      if (!ParsePropertyClassName(&name_1, &name_2) ||
          !AddPropertyClassRange(ranges, strings, negate, name_1, name_2)) {
        ReportError(in_class_escape_state == InClassEscapeState::kInClass
                        ? RegExpError::kInvalidClassPropertyName
                        : RegExpError::kInvalidPropertyName);
      }
      return true;
    }
    default:
      return false;
  }
}

namespace {

// Add |string| to |ranges| if length of |string| == 1, otherwise add |string|
// to |strings|.
void AddClassString(ZoneList<base::uc32>* normalized_string,
                    RegExpTree* regexp_string, ZoneList<CharacterRange>* ranges,
                    CharacterClassStrings* strings, Zone* zone) {
  if (normalized_string->length() == 1) {
    ranges->Add(CharacterRange::Singleton(normalized_string->at(0)), zone);
  } else {
    strings->emplace(normalized_string->ToVector(), regexp_string);
  }
}

}  // namespace

// https://tc39.es/ecma262/#prod-ClassStringDisjunction
template <class CharT>
RegExpTree* RegExpParserImpl<CharT>::ParseClassStringDisjunction(
    ZoneList<CharacterRange>* ranges, CharacterClassStrings* strings) {
  DCHECK(unicode_sets());
  DCHECK_EQ(current(), '\\');
  DCHECK_EQ(Next(), 'q');
  Advance(2);
  if (current() != '{') {
    // Identity escape of 'q' is not allowed in unicode mode.
    return ReportError(RegExpError::kInvalidEscape);
  }
  Advance();

  ZoneList<base::uc32>* string =
      zone()->template New<ZoneList<base::uc32>>(4, zone());
  RegExpTextBuilder::SmallRegExpTreeVector string_storage(zone());
  RegExpTextBuilder string_builder(zone(), &string_storage, flags());

  while (has_more() && current() != '}') {
    if (current() == '|') {
      AddClassString(string, string_builder.ToRegExp(), ranges, strings,
                     zone());
      string = zone()->template New<ZoneList<base::uc32>>(4, zone());
      string_storage.clear();
      Advance();
    } else {
      base::uc32 c = ParseClassSetCharacter(CHECK_FAILED);
      if (ignore_case()) {
#ifdef V8_INTL_SUPPORT
        c = u_foldCase(c, U_FOLD_CASE_DEFAULT);
#else
        c = AsciiAlphaToLower(c);
#endif
      }
      string->Add(c, zone());
      string_builder.AddUnicodeCharacter(c);
    }
  }

  AddClassString(string, string_builder.ToRegExp(), ranges, strings, zone());
  CharacterRange::Canonicalize(ranges);

  // We don't need to handle missing closing '}' here.
  // If the character class is correctly closed, ParseClassSetCharacter will
  // report an error.
  Advance();
  return nullptr;
}

// https://tc39.es/ecma262/#prod-ClassSetOperand
// Tree returned based on type_out:
//  * kNestedClass: RegExpClassSetExpression
//  * For all other types: RegExpClassSetOperand
template <class CharT>
RegExpTree* RegExpParserImpl<CharT>::ParseClassSetOperand(
    const RegExpBuilder* builder, ClassSetOperandType* type_out) {
  ZoneList<CharacterRange>* ranges =
      zone()->template New<ZoneList<CharacterRange>>(1, zone());
  CharacterClassStrings* strings =
      zone()->template New<CharacterClassStrings>(zone());
  base::uc32 character;
  RegExpTree* tree = ParseClassSetOperand(builder, type_out, ranges, strings,
                                          &character CHECK_FAILED);
  DCHECK_IMPLIES(*type_out != ClassSetOperandType::kNestedClass,
                 tree == nullptr);
  DCHECK_IMPLIES(*type_out == ClassSetOperandType::kClassSetCharacter,
                 ranges->is_empty());
  DCHECK_IMPLIES(*type_out == ClassSetOperandType::kClassSetCharacter,
                 strings->empty());
  DCHECK_IMPLIES(*type_out == ClassSetOperandType::kNestedClass,
                 ranges->is_empty());
  DCHECK_IMPLIES(*type_out == ClassSetOperandType::kNestedClass,
                 strings->empty());
  DCHECK_IMPLIES(*type_out == ClassSetOperandType::kNestedClass,
                 tree->IsClassSetExpression());
  // ClassSetRange is only used within ClassSetUnion().
  DCHECK_NE(*type_out, ClassSetOperandType::kClassSetRange);
  // There are no restrictions for kCharacterClassEscape.
  // CharacterClassEscape includes \p{}, which can contain ranges, strings or
  // both and \P{}, which could contain nothing (i.e. \P{Any}).
  if (tree == nullptr) {
    if (*type_out == ClassSetOperandType::kClassSetCharacter) {
      AddMaybeSimpleCaseFoldedRange(ranges,
                                    CharacterRange::Singleton(character));
    }
    tree = zone()->template New<RegExpClassSetOperand>(ranges, strings);
  }
  return tree;
}

// https://tc39.es/ecma262/#prod-ClassSetOperand
// Based on |type_out| either a tree is returned or
// |ranges|/|strings|/|character| modified. If a tree is returned,
// ranges/strings are not modified. If |type_out| is kNestedClass, a tree of
// type RegExpClassSetExpression is returned. If | type_out| is
// kClassSetCharacter, |character| is set and nullptr returned. For all other
// types, |ranges|/|strings|/|character| is modified and nullptr is returned.
template <class CharT>
RegExpTree* RegExpParserImpl<CharT>::ParseClassSetOperand(
    const RegExpBuilder* builder, ClassSetOperandType* type_out,
    ZoneList<CharacterRange>* ranges, CharacterClassStrings* strings,
    base::uc32* character) {
  DCHECK(unicode_sets());
  base::uc32 c = current();
  if (c == '\\') {
    const base::uc32 next = Next();
    if (next == 'q') {
      *type_out = ClassSetOperandType::kClassStringDisjunction;
      ParseClassStringDisjunction(ranges, strings CHECK_FAILED);
      return nullptr;
    }
    static constexpr InClassEscapeState kInClassEscape =
        InClassEscapeState::kInClass;
    const bool add_unicode_case_equivalents = ignore_case();
    if (TryParseCharacterClassEscape(next, kInClassEscape, ranges, strings,
                                     zone(), add_unicode_case_equivalents)) {
      *type_out = ClassSetOperandType::kCharacterClassEscape;
      return nullptr;
    }
  }

  if (c == '[') {
    *type_out = ClassSetOperandType::kNestedClass;
    return ParseCharacterClass(builder);
  }

  *type_out = ClassSetOperandType::kClassSetCharacter;
  c = ParseClassSetCharacter(CHECK_FAILED);
  *character = c;
  return nullptr;
}

template <class CharT>
base::uc32 RegExpParserImpl<CharT>::ParseClassSetCharacter() {
  DCHECK(unicode_sets());
  const base::uc32 c = current();
  if (c == '\\') {
    const base::uc32 next = Next();
    switch (next) {
      case 'b':
        Advance(2);
        return '\b';
      case kEndMarker:
        ReportError(RegExpError::kEscapeAtEndOfPattern);
        return 0;
    }
    static constexpr InClassEscapeState kInClassEscape =
        InClassEscapeState::kInClass;

    bool dummy = false;  // Unused.
    return ParseCharacterEscape(kInClassEscape, &dummy);
  }
  if (IsClassSetSyntaxCharacter(c)) {
    ReportError(RegExpError::kInvalidCharacterInClass);
    return 0;
  }
  if (IsClassSetReservedDoublePunctuator(c)) {
    ReportError(RegExpError::kInvalidClassSetOperation);
    return 0;
  }
  Advance();
  return c;
}

namespace {

bool MayContainStrings(ClassSetOperandType type, RegExpTree* operand) {
  switch (type) {
    case ClassSetOperandType::kClassSetCharacter:
    case ClassSetOperandType::kClassSetRange:
      return false;
    case ClassSetOperandType::kCharacterClassEscape:
    case ClassSetOperandType::kClassStringDisjunction:
      return operand->AsClassSetOperand()->has_strings();
    case ClassSetOperandType::kNestedClass:
      if (operand->IsClassRanges()) return false;
      return operand->AsClassSetExpression()->may_contain_strings();
  }
}

}  // namespace

template <class CharT>
void RegExpParserImpl<CharT>::AddMaybeSimpleCaseFoldedRange(
    ZoneList<CharacterRange>* ranges, CharacterRange new_range) {
  DCHECK(unicode_sets());
  if (ignore_case()) {
    ZoneList<CharacterRange>* new_ranges =
        zone()->template New<ZoneList<CharacterRange>>(2, zone());
    new_ranges->Add(new_range, zone());
    CharacterRange::AddUnicodeCaseEquivalents(new_ranges, zone());
    ranges->AddAll(*new_ranges, zone());
  } else {
    ranges->Add(new_range, zone());
  }
  CharacterRange::Canonicalize(ranges);
}

// https://tc39.es/ecma262/#prod-ClassUnion
template <class CharT>
RegExpTree* RegExpParserImpl<CharT>::ParseClassUnion(
    const RegExpBuilder* builder, bool is_negated, RegExpTree* first_operand,
    ClassSetOperandType first_operand_type, ZoneList<CharacterRange>* ranges,
    CharacterClassStrings* strings, base::uc32 character) {
  DCHECK(unicode_sets());
  ZoneList<RegExpTree*>* operands =
      zone()->template New<ZoneList<RegExpTree*>>(2, zone());
  bool may_contain_strings = false;
  // Add the lhs to operands if necessary.
  // Either the lhs values were added to |ranges|/|strings| (in which case
  // |first_operand| is nullptr), or the lhs was evaluated to a tree and passed
  // as |first_operand| (in which case |ranges| and |strings| are empty).
  if (first_operand != nullptr) {
    may_contain_strings = MayContainStrings(first_operand_type, first_operand);
    operands->Add(first_operand, zone());
  }
  ClassSetOperandType last_type = first_operand_type;
  while (has_more() && current() != ']') {
    if (current() == '-') {
      // Mix of ClassSetRange and ClassSubtraction is not allowed.
      if (Next() == '-') {
        return ReportError(RegExpError::kInvalidClassSetOperation);
      }
      Advance();
      if (!has_more()) {
        // If we reach the end we break out of the loop and let the
        // following code report an error.
        break;
      }
      // If the lhs and rhs around '-' are both ClassSetCharacters, they
      // represent a character range.
      // In case one of them is not a ClassSetCharacter, it is a syntax error,
      // as '-' can not be used unescaped within a class with /v.
      // See
      // https://tc39.es/ecma262/#prod-ClassSetRange
      if (last_type != ClassSetOperandType::kClassSetCharacter) {
        return ReportError(RegExpError::kInvalidCharacterClass);
      }
      base::uc32 from = character;
      ParseClassSetOperand(builder, &last_type, ranges, strings,
                           &character CHECK_FAILED);
      if (last_type != ClassSetOperandType::kClassSetCharacter) {
        return ReportError(RegExpError::kInvalidCharacterClass);
      }
      if (from > character) {
        return ReportError(RegExpError::kOutOfOrderCharacterClass);
      }
      AddMaybeSimpleCaseFoldedRange(ranges,
                                    CharacterRange::Range(from, character));
      last_type = ClassSetOperandType::kClassSetRange;
    } else {
      DCHECK_NE(current(), '-');
      if (last_type == ClassSetOperandType::kClassSetCharacter) {
        AddMaybeSimpleCaseFoldedRange(ranges,
                                      CharacterRange::Singleton(character));
      }
      RegExpTree* operand = ParseClassSetOperand(
          builder, &last_type, ranges, strings, &character CHECK_FAILED);
      if (operand != nullptr) {
        may_contain_strings |= MayContainStrings(last_type, operand);
        // Add the range we started building as operand and reset the current
        // range.
        if (!ranges->is_empty() || !strings->empty()) {
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