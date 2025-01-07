Response:
The user wants me to analyze a C++ source code file related to regular expression parsing in V8. I need to identify its functionalities, relate them to JavaScript if applicable, provide examples, discuss potential programming errors, and summarize its purpose.

**Plan:**

1. **Functionality Analysis:** Read through the code to understand the purpose of each function and code block. Focus on identifying key operations like parsing property class names, adding property class ranges, handling character escapes, parsing class ranges, and dealing with Unicode properties.
2. **JavaScript Relation:** Look for concepts and functionalities that are directly related to JavaScript regular expression syntax and behavior, particularly around Unicode properties and character classes.
3. **JavaScript Examples:** Create simple JavaScript regular expressions that demonstrate the functionalities identified in the C++ code.
4. **Logic Reasoning:**  For specific code blocks, create hypothetical inputs and trace the execution flow to determine the output. Focus on functions like `LookupPropertyValueName` and `ParseClassRanges`.
5. **Common Errors:** Identify potential programmer errors related to regular expressions that the code might be designed to handle or prevent (e.g., invalid escapes, out-of-order ranges).
6. **Summary:** Condense the identified functionalities into a concise summary.
这是v8/src/regexp/regexp-parser.cc的第三部分代码，它主要负责解析正则表达式中关于 Unicode 属性和字符类相关的部分。以下是它的功能归纳：

**功能归纳:**

这部分代码主要处理正则表达式中与 Unicode 字符属性相关的解析，尤其是在字符类（`[]`）内部。它负责识别和处理诸如 `\p{...}` 和 `\P{...}` 这样的 Unicode 属性转义，以及字符类的各种操作。

**具体功能:**

1. **Unicode 属性查找 (`LookupPropertyValueName`, `LookupSpecialPropertyValueName`):**
    *   能够根据给定的 Unicode 属性名和属性值名，在 ICU 库中查找对应的字符范围。
    *   支持处理属性值的别名。
    *   支持特殊的属性名，如 "Any", "ASCII", "Assigned"。
    *   可以根据 `negate` 参数来取属性的补集。

2. **支持的 Unicode 属性检查 (`IsSupportedBinaryProperty`, `IsBinaryPropertyOfStrings`):**
    *   维护一个允许的 Unicode 二进制属性列表，用于确保互操作性。
    *   区分哪些属性可能包含字符串值，这在某些操作中（例如取补集）是不允许的。

3. **Unicode 属性值字符验证 (`IsUnicodePropertyValueCharacter`):**
    *   验证给定的字符是否是合法的 Unicode 属性名或属性值名的一部分。

4. **解析属性类名 (`ParsePropertyClassName`):**
    *   解析 `\p{name}` 或 `\p{name=value}` 形式的 Unicode 属性转义。
    *   将属性名和属性值名分别提取出来。

5. **添加属性类范围 (`AddPropertyClassRange`):**
    *   根据解析出的属性名和属性值名，查找对应的字符范围，并添加到字符类范围列表中。
    *   区分处理二进制属性和枚举属性。
    *   在 Unicode Sets 模式 (`/v`) 下有不同的处理逻辑，例如在取反二进制属性时需要进行大小写折叠。

6. **解析无限长度的十六进制数 (`ParseUnlimitedLengthHexNumber`):**
    *   用于解析 Unicode 代码点。

7. **解析字符转义 (`ParseCharacterEscape`):**
    *   处理各种字符转义序列，如 `\f`, `\n`, `\r`, `\t`, `\v`, `\c`, `\0`, `\x`, `\u`。
    *   根据是否启用 Unicode 模式 (`/u`, `/v`)，对某些转义序列有不同的解释。
    *   在字符类内部和外部，对某些转义序列的处理可能不同。

8. **解析字符类范围 (`ParseClassRanges`):**
    *   解析字符类 `[]` 内部的字符范围，例如 `a-z`, `0-9`。
    *   处理字符类内部的转义字符。
    *   检查范围的顺序，确保起始字符的码点小于等于结束字符的码点。

9. **解析字符类转义 (`ParseClassEscape`):**
    *   处理字符类内部的转义字符，包括 `\b` 和其他通过 `ParseCharacterEscape` 处理的转义。

10. **尝试解析字符类转义 (`TryParseCharacterClassEscape`):**
    *   专门处理字符类内部的特定转义，如 `\d`, `\D`, `\s`, `\S`, `\w`, `\W`, `\p{...}`, `\P{...}`。

11. **添加类字符串 (`AddClassString`):**
    *   辅助函数，用于将解析出的字符串添加到字符类范围或字符串列表中。

12. **解析类字符串析取 (`ParseClassStringDisjunction`):**
    *   在 Unicode Sets 模式下，解析类似 `\q{a|bc|d}` 的结构，表示匹配字符串 "a" 或 "bc" 或 "d"。

13. **解析类集合操作数 (`ParseClassSetOperand`):**
    *   在 Unicode Sets 模式下，解析字符类操作的组成部分，例如单个字符、字符类转义、嵌套的字符类。

14. **解析类集合字符 (`ParseClassSetCharacter`):**
    *   在 Unicode Sets 模式下，解析字符类中的单个字符，处理转义。

15. **添加可能简单的大小写折叠范围 (`AddMaybeSimpleCaseFoldedRange`):**
    *   在 Unicode Sets 模式且忽略大小写时，将字符范围及其简单的大小写等价范围添加到列表中。

16. **解析类联合 (`ParseClassUnion`):**
    *   在 Unicode Sets 模式下，解析字符类的并集操作。

**与 JavaScript 的关系及示例:**

这部分代码直接影响 JavaScript 中正则表达式对 Unicode 属性的支持，尤其是在启用了 Unicode 模式 (`/u`) 或 Unicode Sets 模式 (`/v`) 时。

**JavaScript 示例:**

```javascript
// 使用 Unicode 属性匹配所有数字字符（包括其他语言的数字）
const regex1 = /\p{Number}/u;
console.log(regex1.test("5"));   // 输出: true
console.log(regex1.test("१"));   // 输出: true (梵文数字)
console.log(regex1.test("a"));   // 输出: false

// 使用 Unicode 属性匹配所有非字母字符
const regex2 = /\P{Letter}/u;
console.log(regex2.test("!"));   // 输出: true
console.log(regex2.test("a"));   // 输出: false

// 使用 Unicode 属性匹配特定脚本（例如希腊文）的字符
const regex3 = /\p{Script=Greek}/u;
console.log(regex3.test("α"));   // 输出: true
console.log(regex3.test("a"));   // 输出: false

// 在 Unicode Sets 模式下使用类字符串析取
const regex4 = /[\q{a|bc|d}]/v;
console.log(regex4.test("a"));   // 输出: true
console.log(regex4.test("bc"));  // 输出: true
console.log(regex4.test("d"));   // 输出: true
console.log(regex4.test("ab"));  // 输出: false

// 在 Unicode Sets 模式下使用字符类联合
const regex5 = /[a-z--[aeiou]]/v; // 匹配辅音字母
console.log(regex5.test("b"));   // 输出: true
console.log(regex5.test("a"));   // 输出: false
```

**代码逻辑推理:**

**假设输入:**  正则表达式片段 `\p{Lowercase}` 且处于 Unicode 模式。

**执行流程 (简化):**

1. `ParseClassEscape` 或 `TryParseCharacterClassEscape` 检测到 `\p`.
2. `ParsePropertyClassName` 解析出属性名 `Lowercase`.
3. `AddPropertyClassRange` 被调用，参数 `name_1` 为 "Lowercase"，`name_2` 为空。
4. `AddPropertyClassRange` 内部会调用 `LookupPropertyValueName`，传入 `UCHAR_GENERAL_CATEGORY_MASK` 和 "Lowercase"。
5. `LookupPropertyValueName` 会使用 ICU 库查找所有属于 "Lowercase" 类别的字符的范围。
6. 这些字符范围会被添加到字符类中。

**输出:**  一个包含所有小写字母 Unicode 字符的字符范围集合。

**用户常见的编程错误:**

1. **错误的 Unicode 属性名或属性值名:**  例如，输入 `\p{Lowercases}`，正确的应该是 `\p{Lowercase}`。这会导致正则表达式解析失败。
    ```javascript
    try {
      const regex = /\p{Lowercases}/u; // 错误的属性名
    } catch (e) {
      console.error(e); // 会抛出错误
    }
    ```

2. **在不支持 Unicode 模式下使用 Unicode 属性:** 在没有 `/u` 标志的情况下使用 `\p{...}` 或 `\P{...}` 会导致语法错误。
    ```javascript
    try {
      const regex = /\p{Number}/; // 缺少 /u 标志
    } catch (e) {
      console.error(e); // 某些引擎可能会抛出警告或错误
    }
    ```

3. **字符类范围顺序错误:** 在字符类中，起始字符的码点必须小于等于结束字符的码点。例如 `[z-a]` 是错误的。
    ```javascript
    try {
      const regex = /[z-a]/u;
    } catch (e) {
      console.error(e); // 会抛出错误
    }
    ```

4. **在 Unicode Sets 模式下错误使用 '-'**:  在 `/v` 模式下，未转义的 `-` 只能用于表示字符范围或字符类减法。单独使用或错误组合会报错。
    ```javascript
    try {
      const regex = /[-abc]/v; // 错误，- 没有明确含义
    } catch (e) {
      console.error(e);
    }
    ```

总而言之，这部分代码是 V8 正则表达式引擎处理复杂 Unicode 字符属性和字符类操作的核心组成部分，确保 JavaScript 能够支持符合最新 ECMAScript 规范的正则表达式功能。

Prompt: 
```
这是目录为v8/src/regexp/regexp-parser.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/regexp/regexp-parser.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
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
          
"""


```