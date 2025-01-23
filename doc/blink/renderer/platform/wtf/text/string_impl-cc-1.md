Response:
My goal is to analyze the provided C++ code snippet from `string_impl.cc` and explain its functionality, especially in relation to web technologies like JavaScript, HTML, and CSS. Here's a breakdown of my thought process:

1. **Identify the Core Functionality:**  The code primarily deals with string manipulation. Keywords like `Find`, `ReverseFind`, `StartsWith`, `EndsWith`, `Replace`, and `Compare` immediately stand out. The presence of `IgnoringCase` and `IgnoringASCIICase` variants suggests case-insensitive operations, crucial for web content processing.

2. **Focus on `StringImpl`:** The class `StringImpl` is central. The methods within it operate on the internal representation of strings. Understanding how `StringImpl` stores characters (8-bit vs. 16-bit) is key to understanding the code's branching logic.

3. **Analyze Individual Functions:** I'll go through each function and determine its purpose:
    * **`FindIgnoringCase` and `FindIgnoringASCIICase`:** These clearly implement case-insensitive searching within a string. The `Internal` helper functions suggest an optimization strategy, possibly handling different character encodings efficiently.
    * **`ReverseFind`:**  This searches backward within a string. The hash-based optimization is interesting.
    * **`StartsWith` and `EndsWith`:** Basic prefix and suffix checking. The `IgnoringCase` and `IgnoringASCIICase` variants are consistent with the `Find` methods.
    * **`StartsWithIgnoringCaseAndAccents`:** This is more sophisticated, involving accent-insensitive comparison. The use of `base::i18n::StringSearchIgnoringCaseAndAccents` points to external library support for internationalization.
    * **`ToU16String`:**  Converts the internal string representation to a standard UTF-16 string.
    * **`Replace` (various overloads):** This is a crucial function for string modification. The overloads handle replacing single characters, substrings at specific positions, and all occurrences of a pattern. The logic for handling 8-bit and 16-bit strings separately is important.
    * **`UpconvertedString`:** Explicitly converts an 8-bit string to a 16-bit string.
    * **`Equal` (various overloads):**  String comparison functions, including case-sensitive and case-insensitive versions. The handling of `Atomic` strings suggests potential optimization for frequently used strings.
    * **`CodeUnitCompareIgnoringASCIICase`:**  Provides a fine-grained comparison mechanism, especially useful for sorting and other ordering operations.

4. **Relate to Web Technologies:** This is where I connect the C++ code to higher-level web concepts:
    * **JavaScript:**  JavaScript strings have methods like `indexOf`, `lastIndexOf`, `startsWith`, `endsWith`, `replace`, and comparisons. The C++ functions directly implement the underlying logic for these JavaScript string operations.
    * **HTML:** HTML parsing and processing involve string manipulation. Finding tags, attributes, and content requires searching and comparison. Case-insensitivity is crucial for HTML attribute names and tag names.
    * **CSS:** CSS selectors and property values are strings. Matching selectors and interpreting property values involves string comparisons and manipulations, often case-insensitively.

5. **Identify Assumptions and Potential Issues:**
    * **Input/Output:** For functions like `Find` and `Replace`, I can hypothesize inputs (the string being searched, the search term/pattern, starting index) and the expected output (the index of the match, the new string).
    * **User/Programming Errors:**  Common errors include out-of-bounds access (e.g., providing an `index` beyond the string length), using incorrect case when it matters, and performance implications of frequent string modifications.

6. **Structure the Explanation:** I'll organize my findings logically, starting with a general overview, then diving into specific function groups, and finally connecting them to web technologies and potential issues. I'll use clear examples to illustrate the relationships.

7. **Address the "Part 2" Request:** The prompt specifically mentions this is part 2. I need to synthesize the information from *this* snippet to summarize its function, assuming there's a preceding "part 1". Since "part 1" isn't provided, I'll focus on the capabilities demonstrated within this code alone and infer that "part 1" likely dealt with string creation, destruction, and basic access.

8. **Refine and Review:** I'll reread my explanation to ensure clarity, accuracy, and completeness. I'll check for any jargon that needs explanation and ensure the examples are easy to understand.

By following these steps, I can systematically analyze the C++ code and generate a comprehensive explanation that addresses all aspects of the prompt. The key is to bridge the gap between the low-level C++ implementation and the high-level concepts of web development.
这是`blink/renderer/platform/wtf/text/string_impl.cc`文件的第二部分，延续了第一部分关于字符串操作的实现。 综合这两部分的代码，我们可以归纳一下 `StringImpl` 类的主要功能：

**核心功能：**

`StringImpl` 类是 Blink 引擎中用于存储和操作字符串的核心实现类。 它提供了丰富的功能，包括：

* **基本属性访问:** 获取字符串长度、判断是否为空。
* **查找操作:**
    * `Find()`: 在字符串中查找子串或字符，可以指定起始位置。
    * `ReverseFind()`: 从后向前查找子串或字符。
    * 提供区分大小写 (`Find`) 和忽略大小写 (`FindIgnoringCase`, `FindIgnoringASCIICase`) 的查找方式。
* **前缀和后缀判断:**
    * `StartsWith()`: 判断字符串是否以指定的前缀开始。
    * `EndsWith()`: 判断字符串是否以指定的后缀结束。
    * 提供区分大小写和忽略大小写的判断方式 (`StartsWithIgnoringCase`, `EndsWithIgnoringCase`, `StartsWithIgnoringASCIICase`, `EndsWithIgnoringASCIICase`)，以及忽略重音符号的判断 (`StartsWithIgnoringCaseAndAccents`)。
* **替换操作:**
    * `Replace()`: 提供多种重载，用于替换字符串中的字符或子串。
    * 可以替换单个字符为另一个字符。
    * 可以替换指定位置和长度的子串为另一个字符串。
    * 可以替换所有出现的特定字符或子串为另一个字符串。
* **类型转换:**
    * `ToU16String()`: 将字符串转换为 `std::u16string` 类型。
    * `UpconvertedString()`: 如果字符串是 8-bit 的，则转换为 16-bit 的新字符串。
* **比较操作:**
    * `Equal()`:  比较两个 `StringImpl` 对象或 `StringImpl` 对象与 C 风格字符串的内容是否相等，包括区分大小写的情况。
    * `CodeUnitCompareIgnoringASCIICase()`:  以忽略 ASCII 大小写的方式比较两个字符串的码元。

**与 JavaScript, HTML, CSS 的关系举例说明:**

`StringImpl` 类是 Blink 引擎底层字符串处理的基础，许多 Web 技术的功能都依赖于它。

* **JavaScript:**
    * 当 JavaScript 引擎执行字符串操作方法时，例如 `string.indexOf()`, `string.lastIndexOf()`, `string.startsWith()`, `string.endsWith()`, `string.replace()`,  Blink 引擎底层会调用 `StringImpl` 相应的查找、比较和替换方法来实现这些功能。
    * **假设输入与输出:** 例如，当 JavaScript 代码执行 `'hello world'.indexOf('world')` 时，底层会调用 `StringImpl::Find("world", 0)`，假设输入的字符串是 "hello world"，要查找的子串是 "world"，起始位置是 0，输出结果将是子串 "world" 在 "hello world" 中的起始索引 6。
    * **用户或编程常见的使用错误:**  在 JavaScript 中使用字符串方法时，如果传入错误的参数类型，例如将一个数字传给 `indexOf()` 的查找参数，虽然 JavaScript 会进行类型转换，但在 Blink 底层，可能会导致预期之外的行为或错误，因为 `StringImpl` 的方法通常期望接收字符串类型。

* **HTML:**
    * HTML 解析器在解析 HTML 标签和属性时，会使用 `StringImpl` 来存储和比较标签名、属性名和属性值。例如，在判断一个标签是否是 `<div>` 时，会用到字符串比较功能。
    * **假设输入与输出:** 当 HTML 解析器遇到字符串 `<div class="container">` 时，会提取标签名 "div" 并使用 `StringImpl::Equal("div")` 来判断标签类型。
    * **用户或编程常见的使用错误:**  HTML 中标签名和属性名通常是不区分大小写的，Blink 引擎在处理时会利用 `StringImpl` 的忽略大小写比较功能。如果开发者在 JavaScript 中错误地进行了大小写敏感的比较，可能会导致选择器失效。

* **CSS:**
    * CSS 解析器在解析 CSS 选择器和属性值时，也会使用 `StringImpl` 进行字符串的存储和比较。例如，在匹配 CSS 选择器 `.container` 时，需要比较元素的 `class` 属性值是否包含 "container"。
    * **假设输入与输出:** 当 CSS 引擎需要匹配类名为 "container" 的元素时，它会获取元素的 `class` 属性值，并使用 `StringImpl::Find("container")` 来判断是否匹配。
    * **用户或编程常见的使用错误:** CSS 选择器中的类名是区分大小写的，但属性值在某些情况下可能不区分大小写。Blink 引擎在处理 CSS 时会根据规范使用 `StringImpl` 提供的不同比较方法。如果开发者在 JavaScript 中尝试获取和操作 CSS 样式时，没有考虑到大小写问题，可能会遇到问题。

**本部分的功能归纳:**

这部分代码主要集中在 `StringImpl` 类中**查找、替换和比较字符串**的各种方法实现。它提供了：

* **更复杂的查找功能:** 包括忽略大小写和 ASCII 大小写的查找，以及从后向前查找。
* **字符串的修改功能:** 提供了多种 `Replace` 方法，允许替换单个字符、指定位置的子串以及所有匹配的子串。
* **更全面的比较功能:** 除了基本的相等比较，还提供了忽略大小写和 ASCII 大小写的比较，以及基于码元的比较。
* **类型转换功能:**  方便地将 `StringImpl` 对象转换为 `std::u16string`，并提供了 8-bit 到 16-bit 的转换。

总而言之，这部分代码增强了 `StringImpl` 类的字符串处理能力，使其能够更灵活、更高效地支持 Blink 引擎中各种文本相关的操作，为 JavaScript 引擎、HTML 解析器和 CSS 引擎等上层模块提供了坚实的基础。

### 提示词
```
这是目录为blink/renderer/platform/wtf/text/string_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
match_string.Characters8(), index,
                                      search_length, match_length);
    return FindIgnoringCaseInternal(Characters8() + index,
                                    match_string.Characters16(), index,
                                    search_length, match_length);
  }
  if (match_string.Is8Bit())
    return FindIgnoringCaseInternal(Characters16() + index,
                                    match_string.Characters8(), index,
                                    search_length, match_length);
  return FindIgnoringCaseInternal(Characters16() + index,
                                  match_string.Characters16(), index,
                                  search_length, match_length);
}

template <typename SearchCharacterType, typename MatchCharacterType>
ALWAYS_INLINE static wtf_size_t FindIgnoringASCIICaseInternal(
    const SearchCharacterType* search_characters,
    const MatchCharacterType* match_characters,
    wtf_size_t index,
    wtf_size_t search_length,
    wtf_size_t match_length) {
  // delta is the number of additional times to test; delta == 0 means test only
  // once.
  wtf_size_t delta = search_length - match_length;

  wtf_size_t i = 0;
  // keep looping until we match
  while (!EqualIgnoringASCIICase(search_characters + i, match_characters,
                                 match_length)) {
    if (i == delta)
      return kNotFound;
    ++i;
  }
  return index + i;
}

wtf_size_t StringImpl::FindIgnoringASCIICase(const StringView& match_string,
                                             wtf_size_t index) {
  if (match_string.IsNull()) [[unlikely]] {
    return kNotFound;
  }

  wtf_size_t match_length = match_string.length();
  if (!match_length)
    return std::min(index, length());

  // Check index & matchLength are in range.
  if (index > length())
    return kNotFound;
  wtf_size_t search_length = length() - index;
  if (match_length > search_length)
    return kNotFound;

  if (Is8Bit()) {
    if (match_string.Is8Bit())
      return FindIgnoringASCIICaseInternal(Characters8() + index,
                                           match_string.Characters8(), index,
                                           search_length, match_length);
    return FindIgnoringASCIICaseInternal(Characters8() + index,
                                         match_string.Characters16(), index,
                                         search_length, match_length);
  }
  if (match_string.Is8Bit())
    return FindIgnoringASCIICaseInternal(Characters16() + index,
                                         match_string.Characters8(), index,
                                         search_length, match_length);
  return FindIgnoringASCIICaseInternal(Characters16() + index,
                                       match_string.Characters16(), index,
                                       search_length, match_length);
}

wtf_size_t StringImpl::ReverseFind(UChar c, wtf_size_t index) {
  if (Is8Bit())
    return WTF::ReverseFind(Characters8(), length_, c, index);
  return WTF::ReverseFind(Characters16(), length_, c, index);
}

template <typename SearchCharacterType, typename MatchCharacterType>
ALWAYS_INLINE static wtf_size_t ReverseFindInternal(
    base::span<const SearchCharacterType> search,
    base::span<const MatchCharacterType> match,
    wtf_size_t index) {
  // Optimization: keep a running hash of the strings,
  // only call equal if the hashes match.

  wtf_size_t match_length = base::checked_cast<wtf_size_t>(match.size());
  // delta is the number of additional times to test; delta == 0 means test only
  // once.
  wtf_size_t delta = std::min(
      index, base::checked_cast<wtf_size_t>(search.size() - match_length));

  wtf_size_t search_hash = 0;
  wtf_size_t match_hash = 0;
  for (wtf_size_t i = 0; i < match_length; ++i) {
    search_hash += search[delta + i];
    match_hash += match[i];
  }

  // keep looping until we match
  while (search_hash != match_hash ||
         search.subspan(delta, match_length) != match) {
    if (!delta)
      return kNotFound;
    --delta;
    search_hash -= search[delta + match_length];
    search_hash += search[delta];
  }
  return delta;
}

wtf_size_t StringImpl::ReverseFind(const StringView& match_string,
                                   wtf_size_t index) {
  if (match_string.IsNull()) [[unlikely]] {
    return kNotFound;
  }

  wtf_size_t match_length = match_string.length();
  wtf_size_t our_length = length();
  if (!match_length)
    return std::min(index, our_length);

  // Optimization 1: fast case for strings of length 1.
  if (match_length == 1) {
    if (Is8Bit())
      return WTF::ReverseFind(Characters8(), our_length, match_string[0],
                              index);
    return WTF::ReverseFind(Characters16(), our_length, match_string[0], index);
  }

  // Check index & matchLength are in range.
  if (match_length > our_length)
    return kNotFound;

  if (Is8Bit()) {
    if (match_string.Is8Bit())
      return ReverseFindInternal(Span8(), match_string.Span8(), index);
    return ReverseFindInternal(Span8(), match_string.Span16(), index);
  }
  if (match_string.Is8Bit())
    return ReverseFindInternal(Span16(), match_string.Span8(), index);
  return ReverseFindInternal(Span16(), match_string.Span16(), index);
}

bool StringImpl::StartsWith(UChar character) const {
  return length_ && (*this)[0] == character;
}

bool StringImpl::StartsWith(const StringView& prefix) const {
  if (prefix.length() > length())
    return false;
  if (Is8Bit()) {
    if (prefix.Is8Bit())
      return Equal(Characters8(), prefix.Span8());
    return Equal(Characters8(), prefix.Span16());
  }
  if (prefix.Is8Bit())
    return Equal(Characters16(), prefix.Span8());
  return Equal(Characters16(), prefix.Span16());
}

bool StringImpl::StartsWithIgnoringCase(const StringView& prefix) const {
  if (prefix.length() > length())
    return false;
  if (Is8Bit()) {
    if (prefix.Is8Bit()) {
      return DeprecatedEqualIgnoringCase(Characters8(), prefix.Characters8(),
                                         prefix.length());
    }
    return DeprecatedEqualIgnoringCase(Characters8(), prefix.Characters16(),
                                       prefix.length());
  }
  if (prefix.Is8Bit()) {
    return DeprecatedEqualIgnoringCase(Characters16(), prefix.Characters8(),
                                       prefix.length());
  }
  return DeprecatedEqualIgnoringCase(Characters16(), prefix.Characters16(),
                                     prefix.length());
}

bool StringImpl::StartsWithIgnoringCaseAndAccents(
    const StringView& prefix) const {
  std::u16string s = ToU16String();
  std::u16string p = ::WTF::ToU16String(prefix);
  size_t match_index = 1U;

  if (base::i18n::StringSearchIgnoringCaseAndAccents(
          p, s, &match_index,
          /*match_length=*/nullptr)) {
    return match_index == 0U;
  }

  return false;
}

std::u16string StringImpl::ToU16String() const {
  if (Is8Bit()) {
    return ::WTF::ToU16String(Characters8(), length());
  }

  return ::WTF::ToU16String(Characters16(), length());
}

bool StringImpl::StartsWithIgnoringASCIICase(const StringView& prefix) const {
  if (prefix.length() > length())
    return false;
  if (Is8Bit()) {
    if (prefix.Is8Bit())
      return EqualIgnoringASCIICase(Characters8(), prefix.Characters8(),
                                    prefix.length());
    return EqualIgnoringASCIICase(Characters8(), prefix.Characters16(),
                                  prefix.length());
  }
  if (prefix.Is8Bit())
    return EqualIgnoringASCIICase(Characters16(), prefix.Characters8(),
                                  prefix.length());
  return EqualIgnoringASCIICase(Characters16(), prefix.Characters16(),
                                prefix.length());
}

bool StringImpl::EndsWith(UChar character) const {
  return length_ && (*this)[length_ - 1] == character;
}

bool StringImpl::EndsWith(const StringView& suffix) const {
  if (suffix.length() > length())
    return false;
  wtf_size_t start_offset = length() - suffix.length();
  if (Is8Bit()) {
    if (suffix.Is8Bit())
      return Equal(Characters8() + start_offset, suffix.Span8());
    return Equal(Characters8() + start_offset, suffix.Span16());
  }
  if (suffix.Is8Bit())
    return Equal(Characters16() + start_offset, suffix.Span8());
  return Equal(Characters16() + start_offset, suffix.Span16());
}

bool StringImpl::EndsWithIgnoringCase(const StringView& suffix) const {
  if (suffix.length() > length())
    return false;
  wtf_size_t start_offset = length() - suffix.length();
  if (Is8Bit()) {
    if (suffix.Is8Bit()) {
      return DeprecatedEqualIgnoringCase(Characters8() + start_offset,
                                         suffix.Characters8(), suffix.length());
    }
    return DeprecatedEqualIgnoringCase(Characters8() + start_offset,
                                       suffix.Characters16(), suffix.length());
  }
  if (suffix.Is8Bit()) {
    return DeprecatedEqualIgnoringCase(Characters16() + start_offset,
                                       suffix.Characters8(), suffix.length());
  }
  return DeprecatedEqualIgnoringCase(Characters16() + start_offset,
                                     suffix.Characters16(), suffix.length());
}

bool StringImpl::EndsWithIgnoringASCIICase(const StringView& suffix) const {
  if (suffix.length() > length())
    return false;
  wtf_size_t start_offset = length() - suffix.length();
  if (Is8Bit()) {
    if (suffix.Is8Bit())
      return EqualIgnoringASCIICase(Characters8() + start_offset,
                                    suffix.Characters8(), suffix.length());
    return EqualIgnoringASCIICase(Characters8() + start_offset,
                                  suffix.Characters16(), suffix.length());
  }
  if (suffix.Is8Bit())
    return EqualIgnoringASCIICase(Characters16() + start_offset,
                                  suffix.Characters8(), suffix.length());
  return EqualIgnoringASCIICase(Characters16() + start_offset,
                                suffix.Characters16(), suffix.length());
}

scoped_refptr<StringImpl> StringImpl::Replace(UChar old_c, UChar new_c) {
  if (old_c == new_c)
    return this;

  if (Find(old_c) == kNotFound)
    return this;

  if (Is8Bit()) {
    if (new_c <= 0xff) {
      base::span<LChar> data8;
      scoped_refptr<StringImpl> new_impl = CreateUninitialized(length_, data8);
      CopyAndReplace(data8, Span8(), static_cast<LChar>(old_c),
                     static_cast<LChar>(new_c));
      return new_impl;
    }

    // There is the possibility we need to up convert from 8 to 16 bit,
    // create a 16 bit string for the result.
    base::span<UChar> data16;
    scoped_refptr<StringImpl> new_impl = CreateUninitialized(length_, data16);
    CopyAndReplace(data16, Span8(), old_c, new_c);
    return new_impl;
  }

  base::span<UChar> data16;
  scoped_refptr<StringImpl> new_impl = CreateUninitialized(length_, data16);
  CopyAndReplace(data16, Span16(), old_c, new_c);
  return new_impl;
}

// TODO(esprehn): Passing a null replacement is the same as empty string for
// this method but all others treat null as a no-op. We should choose one
// behavior.
scoped_refptr<StringImpl> StringImpl::Replace(wtf_size_t position,
                                              wtf_size_t length_to_replace,
                                              const StringView& string) {
  position = std::min(position, length());
  length_to_replace = std::min(length_to_replace, length() - position);
  wtf_size_t length_to_insert = string.length();
  if (!length_to_replace && !length_to_insert)
    return this;

  CHECK_LT((length() - length_to_replace),
           (numeric_limits<wtf_size_t>::max() - length_to_insert));

  if (Is8Bit() && (string.IsNull() || string.Is8Bit())) {
    LChar* data;
    scoped_refptr<StringImpl> new_impl = CreateUninitialized(
        length() - length_to_replace + length_to_insert, data);
    memcpy(data, Characters8(), position * sizeof(LChar));
    if (!string.IsNull())
      memcpy(data + position, string.Characters8(),
             length_to_insert * sizeof(LChar));
    memcpy(data + position + length_to_insert,
           Characters8() + position + length_to_replace,
           (length() - position - length_to_replace) * sizeof(LChar));
    return new_impl;
  }
  UChar* data;
  scoped_refptr<StringImpl> new_impl = CreateUninitialized(
      length() - length_to_replace + length_to_insert, data);
  if (Is8Bit())
    for (wtf_size_t i = 0; i < position; ++i)
      data[i] = Characters8()[i];
  else
    memcpy(data, Characters16(), position * sizeof(UChar));
  if (!string.IsNull()) {
    if (string.Is8Bit())
      for (wtf_size_t i = 0; i < length_to_insert; ++i)
        data[i + position] = string.Characters8()[i];
    else
      memcpy(data + position, string.Characters16(),
             length_to_insert * sizeof(UChar));
  }
  if (Is8Bit()) {
    for (wtf_size_t i = 0; i < length() - position - length_to_replace; ++i)
      data[i + position + length_to_insert] =
          Characters8()[i + position + length_to_replace];
  } else {
    memcpy(data + position + length_to_insert,
           Characters16() + position + length_to_replace,
           (length() - position - length_to_replace) * sizeof(UChar));
  }
  return new_impl;
}

scoped_refptr<StringImpl> StringImpl::Replace(UChar pattern,
                                              const StringView& replacement) {
  if (replacement.IsNull())
    return this;
  if (replacement.Is8Bit())
    return Replace(pattern, replacement.Characters8(), replacement.length());
  return Replace(pattern, replacement.Characters16(), replacement.length());
}

scoped_refptr<StringImpl> StringImpl::Replace(UChar pattern,
                                              const LChar* replacement,
                                              wtf_size_t rep_str_length) {
  DCHECK(replacement);

  wtf_size_t src_segment_start = 0;
  wtf_size_t match_count = 0;

  // Count the matches.
  while ((src_segment_start = Find(pattern, src_segment_start)) != kNotFound) {
    ++match_count;
    ++src_segment_start;
  }

  // If we have 0 matches then we don't have to do any more work.
  if (!match_count)
    return this;

  CHECK(!rep_str_length ||
        match_count <= numeric_limits<wtf_size_t>::max() / rep_str_length);

  wtf_size_t replace_size = match_count * rep_str_length;
  wtf_size_t new_size = length_ - match_count;
  CHECK_LT(new_size, (numeric_limits<wtf_size_t>::max() - replace_size));

  new_size += replace_size;

  // Construct the new data.
  wtf_size_t src_segment_end;
  wtf_size_t src_segment_length;
  src_segment_start = 0;
  wtf_size_t dst_offset = 0;

  if (Is8Bit()) {
    LChar* data;
    scoped_refptr<StringImpl> new_impl = CreateUninitialized(new_size, data);

    while ((src_segment_end = Find(pattern, src_segment_start)) != kNotFound) {
      src_segment_length = src_segment_end - src_segment_start;
      memcpy(data + dst_offset, Characters8() + src_segment_start,
             src_segment_length * sizeof(LChar));
      dst_offset += src_segment_length;
      memcpy(data + dst_offset, replacement, rep_str_length * sizeof(LChar));
      dst_offset += rep_str_length;
      src_segment_start = src_segment_end + 1;
    }

    src_segment_length = length_ - src_segment_start;
    memcpy(data + dst_offset, Characters8() + src_segment_start,
           src_segment_length * sizeof(LChar));

    DCHECK_EQ(dst_offset + src_segment_length, new_impl->length());

    return new_impl;
  }

  UChar* data;
  scoped_refptr<StringImpl> new_impl = CreateUninitialized(new_size, data);

  while ((src_segment_end = Find(pattern, src_segment_start)) != kNotFound) {
    src_segment_length = src_segment_end - src_segment_start;
    memcpy(data + dst_offset, Characters16() + src_segment_start,
           src_segment_length * sizeof(UChar));

    dst_offset += src_segment_length;
    for (wtf_size_t i = 0; i < rep_str_length; ++i)
      data[i + dst_offset] = replacement[i];

    dst_offset += rep_str_length;
    src_segment_start = src_segment_end + 1;
  }

  src_segment_length = length_ - src_segment_start;
  memcpy(data + dst_offset, Characters16() + src_segment_start,
         src_segment_length * sizeof(UChar));

  DCHECK_EQ(dst_offset + src_segment_length, new_impl->length());

  return new_impl;
}

scoped_refptr<StringImpl> StringImpl::Replace(UChar pattern,
                                              const UChar* replacement,
                                              wtf_size_t rep_str_length) {
  DCHECK(replacement);

  wtf_size_t src_segment_start = 0;
  wtf_size_t match_count = 0;

  // Count the matches.
  while ((src_segment_start = Find(pattern, src_segment_start)) != kNotFound) {
    ++match_count;
    ++src_segment_start;
  }

  // If we have 0 matches then we don't have to do any more work.
  if (!match_count)
    return this;

  CHECK(!rep_str_length ||
        match_count <= numeric_limits<wtf_size_t>::max() / rep_str_length);

  wtf_size_t replace_size = match_count * rep_str_length;
  wtf_size_t new_size = length_ - match_count;
  CHECK_LT(new_size, (numeric_limits<wtf_size_t>::max() - replace_size));

  new_size += replace_size;

  // Construct the new data.
  wtf_size_t src_segment_end;
  wtf_size_t src_segment_length;
  src_segment_start = 0;
  wtf_size_t dst_offset = 0;

  if (Is8Bit()) {
    UChar* data;
    scoped_refptr<StringImpl> new_impl = CreateUninitialized(new_size, data);

    while ((src_segment_end = Find(pattern, src_segment_start)) != kNotFound) {
      src_segment_length = src_segment_end - src_segment_start;
      for (wtf_size_t i = 0; i < src_segment_length; ++i)
        data[i + dst_offset] = Characters8()[i + src_segment_start];

      dst_offset += src_segment_length;
      memcpy(data + dst_offset, replacement, rep_str_length * sizeof(UChar));

      dst_offset += rep_str_length;
      src_segment_start = src_segment_end + 1;
    }

    src_segment_length = length_ - src_segment_start;
    for (wtf_size_t i = 0; i < src_segment_length; ++i)
      data[i + dst_offset] = Characters8()[i + src_segment_start];

    DCHECK_EQ(dst_offset + src_segment_length, new_impl->length());

    return new_impl;
  }

  UChar* data;
  scoped_refptr<StringImpl> new_impl = CreateUninitialized(new_size, data);

  while ((src_segment_end = Find(pattern, src_segment_start)) != kNotFound) {
    src_segment_length = src_segment_end - src_segment_start;
    memcpy(data + dst_offset, Characters16() + src_segment_start,
           src_segment_length * sizeof(UChar));

    dst_offset += src_segment_length;
    memcpy(data + dst_offset, replacement, rep_str_length * sizeof(UChar));

    dst_offset += rep_str_length;
    src_segment_start = src_segment_end + 1;
  }

  src_segment_length = length_ - src_segment_start;
  memcpy(data + dst_offset, Characters16() + src_segment_start,
         src_segment_length * sizeof(UChar));

  DCHECK_EQ(dst_offset + src_segment_length, new_impl->length());

  return new_impl;
}

scoped_refptr<StringImpl> StringImpl::Replace(const StringView& pattern,
                                              const StringView& replacement) {
  if (pattern.IsNull() || replacement.IsNull())
    return this;

  wtf_size_t pattern_length = pattern.length();
  if (!pattern_length)
    return this;

  wtf_size_t rep_str_length = replacement.length();
  wtf_size_t src_segment_start = 0;
  wtf_size_t match_count = 0;

  // Count the matches.
  while ((src_segment_start = Find(pattern, src_segment_start)) != kNotFound) {
    ++match_count;
    src_segment_start += pattern_length;
  }

  // If we have 0 matches, we don't have to do any more work
  if (!match_count)
    return this;

  wtf_size_t new_size = length_ - match_count * pattern_length;
  CHECK(!rep_str_length ||
        match_count <= numeric_limits<wtf_size_t>::max() / rep_str_length);

  CHECK_LE(new_size,
           (numeric_limits<wtf_size_t>::max() - match_count * rep_str_length));

  new_size += match_count * rep_str_length;

  // Construct the new data
  wtf_size_t src_segment_end;
  wtf_size_t src_segment_length;
  src_segment_start = 0;
  wtf_size_t dst_offset = 0;
  bool src_is_8bit = Is8Bit();
  bool replacement_is_8bit = replacement.Is8Bit();

  // There are 4 cases:
  // 1. This and replacement are both 8 bit.
  // 2. This and replacement are both 16 bit.
  // 3. This is 8 bit and replacement is 16 bit.
  // 4. This is 16 bit and replacement is 8 bit.
  if (src_is_8bit && replacement_is_8bit) {
    // Case 1
    LChar* data;
    scoped_refptr<StringImpl> new_impl = CreateUninitialized(new_size, data);
    while ((src_segment_end = Find(pattern, src_segment_start)) != kNotFound) {
      src_segment_length = src_segment_end - src_segment_start;
      memcpy(data + dst_offset, Characters8() + src_segment_start,
             src_segment_length * sizeof(LChar));
      dst_offset += src_segment_length;
      memcpy(data + dst_offset, replacement.Characters8(),
             rep_str_length * sizeof(LChar));
      dst_offset += rep_str_length;
      src_segment_start = src_segment_end + pattern_length;
    }

    src_segment_length = length_ - src_segment_start;
    memcpy(data + dst_offset, Characters8() + src_segment_start,
           src_segment_length * sizeof(LChar));

    DCHECK_EQ(dst_offset + src_segment_length, new_impl->length());

    return new_impl;
  }

  UChar* data;
  scoped_refptr<StringImpl> new_impl = CreateUninitialized(new_size, data);
  while ((src_segment_end = Find(pattern, src_segment_start)) != kNotFound) {
    src_segment_length = src_segment_end - src_segment_start;
    if (src_is_8bit) {
      // Case 3.
      for (wtf_size_t i = 0; i < src_segment_length; ++i)
        data[i + dst_offset] = Characters8()[i + src_segment_start];
    } else {
      // Case 2 & 4.
      memcpy(data + dst_offset, Characters16() + src_segment_start,
             src_segment_length * sizeof(UChar));
    }
    dst_offset += src_segment_length;
    if (replacement_is_8bit) {
      // Cases 2 & 3.
      for (wtf_size_t i = 0; i < rep_str_length; ++i)
        data[i + dst_offset] = replacement.Characters8()[i];
    } else {
      // Case 4
      memcpy(data + dst_offset, replacement.Characters16(),
             rep_str_length * sizeof(UChar));
    }
    dst_offset += rep_str_length;
    src_segment_start = src_segment_end + pattern_length;
  }

  src_segment_length = length_ - src_segment_start;
  if (src_is_8bit) {
    // Case 3.
    for (wtf_size_t i = 0; i < src_segment_length; ++i)
      data[i + dst_offset] = Characters8()[i + src_segment_start];
  } else {
    // Cases 2 & 4.
    memcpy(data + dst_offset, Characters16() + src_segment_start,
           src_segment_length * sizeof(UChar));
  }

  DCHECK_EQ(dst_offset + src_segment_length, new_impl->length());

  return new_impl;
}

scoped_refptr<StringImpl> StringImpl::UpconvertedString() {
  if (Is8Bit())
    return String::Make16BitFrom8BitSource(Span8()).ReleaseImpl();
  return this;
}

static inline bool StringImplContentEqual(const StringImpl* a,
                                          const StringImpl* b) {
  wtf_size_t a_length = a->length();
  wtf_size_t b_length = b->length();
  if (a_length != b_length)
    return false;

  if (!a_length)
    return true;

  if (a->Is8Bit()) {
    if (b->Is8Bit())
      return Equal(a->Characters8(), b->Span8());

    return Equal(a->Characters8(), b->Span16());
  }

  if (b->Is8Bit())
    return Equal(a->Characters16(), b->Span8());

  return Equal(a->Characters16(), b->Span16());
}

bool Equal(const StringImpl* a, const StringImpl* b) {
  if (a == b)
    return true;
  if (!a || !b)
    return false;
  if (a->IsAtomic() && b->IsAtomic())
    return false;

  return StringImplContentEqual(a, b);
}

template <typename CharType>
inline bool EqualInternal(const StringImpl* a, base::span<const CharType> b) {
  if (!a)
    return !b.data();
  if (!b.data()) {
    return false;
  }

  if (a->length() != b.size()) {
    return false;
  }
  if (a->Is8Bit())
    return Equal(a->Characters8(), b);
  return Equal(a->Characters16(), b);
}

bool Equal(const StringImpl* a, base::span<const LChar> b) {
  return EqualInternal(a, b);
}

bool Equal(const StringImpl* a, base::span<const UChar> b) {
  return EqualInternal(a, b);
}

template <typename StringType>
bool EqualToCString(const StringType* a, const LChar* b) {
  DCHECK(b);
  wtf_size_t length = a->length();

  if (a->Is8Bit()) {
    const LChar* a_ptr = a->Characters8();
    for (wtf_size_t i = 0; i != length; ++i) {
      LChar bc = b[i];
      LChar ac = a_ptr[i];
      if (!bc)
        return false;
      if (ac != bc)
        return false;
    }

    return !b[length];
  }

  const UChar* a_ptr = a->Characters16();
  for (wtf_size_t i = 0; i != length; ++i) {
    LChar bc = b[i];
    if (!bc)
      return false;
    if (a_ptr[i] != bc)
      return false;
  }

  return !b[length];
}

bool EqualToCString(const StringImpl* a, const char* latin1) {
  if (!a) {
    return !latin1;
  }
  return EqualToCString(a, reinterpret_cast<const LChar*>(latin1));
}

bool EqualToCString(const StringView& a, const char* latin1) {
  return EqualToCString(&a, reinterpret_cast<const LChar*>(latin1));
}

bool EqualNonNull(const StringImpl* a, const StringImpl* b) {
  DCHECK(a);
  DCHECK(b);
  if (a == b)
    return true;

  return StringImplContentEqual(a, b);
}

bool EqualIgnoringNullity(StringImpl* a, StringImpl* b) {
  if (!a && b && !b->length())
    return true;
  if (!b && a && !a->length())
    return true;
  return Equal(a, b);
}

template <typename CharacterType1, typename CharacterType2>
int CodeUnitCompareIgnoringASCIICase(wtf_size_t l1,
                                     wtf_size_t l2,
                                     const CharacterType1* c1,
                                     const CharacterType2* c2) {
  const wtf_size_t lmin = l1 < l2 ? l1 : l2;
  wtf_size_t pos = 0;
  while (pos < lmin && ToASCIILower(*c1) == ToASCIILower(*c2)) {
    ++c1;
    ++c2;
    ++pos;
  }

  if (pos < lmin)
    return (ToASCIILower(c1[0]) > ToASCIILower(c2[0])) ? 1 : -1;

  if (l1 == l2)
    return 0;

  return (l1 > l2) ? 1 : -1;
}

template <typename CharacterType>
int CodeUnitCompareIgnoringASCIICase(const StringImpl* string1,
                                     const CharacterType* string2,
                                     wtf_size_t length2) {
  if (!string1)
    return length2 > 0 ? -1 : 0;

  wtf_size_t length1 = string1->length();
  if (!string2)
    return length1 > 0 ? 1 : 0;

  if (string1->Is8Bit()) {
    return CodeUnitCompareIgnoringASCIICase(length1, length2,
                                            string1->Characters8(), string2);
  }
  return CodeUnitCompareIgnoringASCIICase(length1, length2,
                                          string1->Characters16(), string2);
}

int CodeUnitCompareIgnoringASCIICase(const StringImpl* string1,
                                     const LChar* string2) {
  return CodeUnitCompareIgnoringASCIICase(
      string1, string2,
      string2 ? strlen(reinterpret_cast<const char*>(string2)) : 0);
}

int CodeUnitCompareIgnoringASCIICase(const StringImpl* string1,
                                     const StringImpl* string2) {
  if (!string2)
    return string1 && string1->length() > 0 ? 1 : 0;
  return VisitCharacters(*string2, [string1](auto chars) {
    return CodeUnitCompareIgnoringASCIICase(string1, chars.data(),
                                            chars.size());
  });
}

}  // namespace WTF
```