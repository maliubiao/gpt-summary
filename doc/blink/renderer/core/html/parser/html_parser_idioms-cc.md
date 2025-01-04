Response:
Let's break down the thought process for analyzing the `html_parser_idioms.cc` file.

1. **Understand the Goal:** The core task is to understand the *functionality* of this specific Chromium source code file and relate it to web technologies like HTML, CSS, and JavaScript. We also need to consider potential usage errors and illustrate with examples.

2. **Initial Scan and Keywords:**  Start by skimming the code for obvious keywords and patterns. Look for:
    * `#include`:  This tells us about dependencies. `html_names.h`, `wtf/`, and `<limits>` are immediately apparent. This suggests the file deals with HTML-specific things and low-level string/data manipulation (WTF = Web Template Framework).
    * Function names:  `StripLeadingAndTrailingHTMLSpaces`, `SplitOnASCIIWhitespace`, `SerializeForNumberType`, `ParseToDecimalForNumberType`, `ParseToDoubleForNumberType`, `ParseHTMLInteger`, `ParseHTMLNonNegativeInteger`, `ParseHTMLListOfFloatingPointNumbers`, `ExtractCharset`, `EncodingFromMetaAttributes`, `ThreadSafeMatch`, `AttemptStaticStringCreation`. These names are highly descriptive and provide strong clues about the file's purpose.
    * Comments:  Pay attention to comments, especially those referencing specific HTML specifications (like WHATWG). This helps contextualize the code.
    * Namespaces: The `blink` namespace confirms this is part of the Blink rendering engine.
    * Templates: The use of templates (`template <typename CharacterType>`) suggests the code is designed to work with different character types (likely `char` and `wchar_t` for ASCII and UTF-16).

3. **Categorize Functions:** Group the functions based on their apparent purpose:
    * **String Manipulation:** `StripLeadingAndTrailingHTMLSpaces`, `SplitOnASCIIWhitespace`. These clearly deal with cleaning and splitting strings, likely for processing HTML attributes or text content.
    * **Number Parsing/Serialization:** `SerializeForNumberType`, `ParseToDecimalForNumberType`, `ParseToDoubleForNumberType`, `ParseHTMLInteger`, `ParseHTMLNonNegativeInteger`, `ParseHTMLClampedNonNegativeInteger`, `ParseHTMLListOfFloatingPointNumbers`. These are dedicated to converting strings to numbers (integers, floats, decimals) and vice-versa, specifically following HTML parsing rules.
    * **Character Encoding:** `ExtractCharset`, `EncodingFromMetaAttributes`. These functions are related to detecting and extracting character encoding information from HTML meta tags.
    * **String/Name Matching:** `ThreadSafeMatch`. This suggests safe comparison of strings, possibly for comparing HTML tag or attribute names.
    * **Optimization:** `AttemptStaticStringCreation`. This hints at an optimization strategy using pre-existing static strings.

4. **Relate to Web Technologies:** Now, connect the categorized functions to HTML, CSS, and JavaScript:
    * **HTML:**  The majority of the functions directly support HTML parsing. Parsing integers and floats is needed for processing attribute values like `width`, `height`, and numeric input values. Character encoding detection is crucial for correctly interpreting HTML content. Stripping whitespace and splitting strings is necessary for handling attributes with multiple values (e.g., `class`).
    * **CSS:** While not directly manipulating CSS *properties*, the parsing of numbers might be indirectly used when processing inline styles or certain CSS-related HTML attributes (though dedicated CSS parsing exists elsewhere).
    * **JavaScript:**  JavaScript interacts with the DOM, which is built by the HTML parser. The parsing of numeric attributes influences how JavaScript can access and manipulate these values. For instance, if an HTML attribute like `data-count=" 123 "` is parsed, JavaScript will receive the cleaned number.

5. **Illustrate with Examples:**  For each category, create concrete examples demonstrating the function's behavior. Think about common HTML scenarios:
    * Whitespace trimming in attribute values.
    * Splitting class names.
    * Parsing numeric input values.
    * Extracting the charset from a `<meta>` tag.
    * Handling invalid numeric input.

6. **Consider Edge Cases and Errors:** Think about what could go wrong:
    * Invalid input formats for numbers.
    * Missing or incorrect charset declarations.
    * Typos in attribute names.
    * Leading/trailing spaces causing unexpected behavior if not handled.

7. **Logical Reasoning (Input/Output):** For functions with clear transformations (like stripping whitespace or parsing numbers), define a few simple input/output pairs to illustrate the logic.

8. **Structure the Answer:** Organize the information logically:
    * Start with a general overview of the file's purpose.
    * List the key functionalities as bullet points.
    * For each functionality, provide:
        * A concise description.
        * Examples of its relationship to HTML, CSS, or JavaScript.
        * Input/output examples (where applicable).
        * Common usage errors with illustrations.

9. **Review and Refine:** Read through the generated answer, ensuring clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. For example, initially, I might not have explicitly mentioned the "thread-safe" aspect of `ThreadSafeMatch`, but reviewing the function name prompts me to include that detail. Similarly, emphasizing the adherence to HTML specifications is crucial.

This systematic approach helps to break down the seemingly complex task of understanding a source code file into smaller, manageable steps, ensuring a comprehensive and informative analysis.
这个 `html_parser_idioms.cc` 文件是 Chromium Blink 引擎中 HTML 解析器的一部分，它包含了一系列用于处理 HTML 解析过程中的常见任务和模式的实用工具函数。  这些函数旨在简化和标准化 HTML 解析器的实现。

以下是它的一些主要功能：

**1. 字符串处理 (String Handling):**

* **`StripLeadingAndTrailingHTMLSpaces(const String& string)`:**
    * **功能:**  移除字符串开头和结尾的 HTML 空格符（空格、制表符、换行符、回车符、换页符）。
    * **与 HTML 的关系:** 在 HTML 解析过程中，很多时候需要清理属性值或文本内容中的多余空格。例如，在解析 HTML 属性时，浏览器需要去除属性值周围的空白。
    * **举例说明:**
        * **输入:** `"  value with spaces  \t\n"`
        * **输出:** `"value with spaces"`
* **`SplitOnASCIIWhitespace(const String& input)`:**
    * **功能:**  将字符串按照 ASCII 空白符分割成多个子字符串。
    * **与 HTML 的关系:**  用于处理 HTML 中以空格分隔的属性值，例如 `class` 属性。
    * **举例说明:**
        * **输入:** `"class1  class2\tclass3"`
        * **输出:** `{"class1", "class2", "class3"}`

**2. 数字解析和序列化 (Number Parsing and Serialization):**

* **`SerializeForNumberType(const Decimal& number)` 和 `SerializeForNumberType(double number)`:**
    * **功能:** 将数字（`Decimal` 类型或 `double` 类型）序列化成符合 HTML 规范的字符串表示形式。
    * **与 HTML 的关系:** 用于将内部表示的数字值转换成 HTML 属性值或文本内容。
    * **举例说明:**
        * **输入 (Decimal):** `Decimal(0)`
        * **输出:** `"0"`
        * **输入 (double):** `0.123`
        * **输出:** `"0.123"`
* **`ParseToDecimalForNumberType(const String& string, const Decimal& fallback_value)` 和 `ParseToDoubleForNumberType(const String& string, double fallback_value)`:**
    * **功能:**  将字符串解析为数字（`Decimal` 或 `double` 类型），如果解析失败则返回提供的回退值。  这些函数遵循 HTML5 规范中关于解析浮点数的规则。
    * **与 HTML 的关系:**  用于解析 HTML 属性中的数字值，例如 `<input type="number">` 元素的 `value` 属性。
    * **假设输入与输出:**
        * **输入 (String):** `"123.45"`，**输出 (Decimal/double):** `123.45`
        * **输入 (String):** `"invalid"`，**输出 (Decimal/double):** `fallback_value`
    * **用户或编程常见的使用错误:**
        * **输入包含无效字符:**  用户可能在数字输入框中输入字母或其他非数字字符。例如，输入 `"12a3" 会导致解析失败，返回回退值。
        * **期待特定的格式:**  开发者可能假设用户总是会输入特定格式的数字，而没有考虑到用户输入可能包含空格或其他分隔符，导致解析失败。
* **`ParseHTMLInteger(const String& input, int& value)`:**
    * **功能:** 将字符串解析为整数，遵循 HTML 中解析整数的规则。
    * **与 HTML 的关系:** 用于解析 HTML 属性中的整数值，例如 `width` 或 `height` 属性。
    * **假设输入与输出:**
        * **输入:** `"  123  "`，**输出:** `true`，`value` 被设置为 `123`
        * **输入:** `"abc"`，**输出:** `false`
* **`ParseHTMLNonNegativeInteger(const String& input, unsigned& value)` 和 `ParseHTMLClampedNonNegativeInteger(...)`:**
    * **功能:**  将字符串解析为非负整数，遵循 HTML 规范。 `ParseHTMLClampedNonNegativeInteger` 还会将结果限制在给定的最小值和最大值之间。
    * **与 HTML 的关系:**  用于解析 HTML 中需要非负整数的属性，例如 `tabindex` 或 `<input type="number">` 元素的 `min` 和 `max` 属性。
    * **假设输入与输出:**
        * **输入:** `"10"`，**输出:** `true`，`value` 被设置为 `10`
        * **输入:** `"-5"`，**输出:** `false`
        * **输入:** `"100"`, `min = 0`, `max = 50`，**输出:** `true`, `value` 被设置为 `50` (Clamp 发生)
    * **用户或编程常见的使用错误:** 用户可能在需要非负整数的地方输入负数，导致解析失败或被限制到最小值。
* **`ParseHTMLListOfFloatingPointNumbers(const String& input)`:**
    * **功能:**  将一个包含以空格或逗号/分号分隔的浮点数的字符串解析为一个 `double` 类型的向量。
    * **与 HTML 的关系:** 用于解析某些接受浮点数列表的 HTML 属性或 CSS 样式值（尽管 CSS 解析通常在其他地方处理）。
    * **假设输入与输出:**
        * **输入:** `"1.0, 2.5  3.7;4.2"`
        * **输出:** `{1.0, 2.5, 3.7, 4.2}`
    * **用户或编程常见的使用错误:** 用户可能使用其他分隔符，或者在数字之间添加了额外的非数字字符，导致解析结果不符合预期。

**3. 字符编码处理 (Character Encoding Handling):**

* **`ExtractCharset(const String& value)`:**
    * **功能:** 从类似 HTML `content` 属性值的字符串中提取字符集信息。
    * **与 HTML 的关系:** 用于解析 `<meta>` 标签的 `content` 属性，以确定文档的字符编码。
    * **假设输入与输出:**
        * **输入:** `"text/html; charset=UTF-8"`
        * **输出:** `"UTF-8"`
        * **输入:** `"text/html"`
        * **输出:** `""`
* **`EncodingFromMetaAttributes(const HTMLAttributeList& attributes)`:**
    * **功能:**  根据 HTML `<meta>` 标签的属性列表（例如 `http-equiv="Content-Type"` 和 `charset` 或 `content`）确定文档的字符编码。
    * **与 HTML 的关系:**  核心功能，用于解析 HTML 文档的字符编码声明。
    * **举例说明:**
        * **输入:**  `{{"http-equiv", "Content-Type"}, {"content", "text/html; charset=ISO-8859-1"}}`
        * **输出:** `WTF::TextEncoding("ISO-8859-1")`
        * **输入:** `{{"charset", "UTF-8"}}`
        * **输出:** `WTF::TextEncoding("UTF-8")`
    * **用户或编程常见的使用错误:**  HTML 作者可能在 `<meta>` 标签中使用了错误的字符集名称，或者同时使用了 `charset` 属性和 `http-equiv="Content-Type"` 且声明了不同的字符集，导致浏览器选择了错误的编码。

**4. 其他实用工具 (Other Utilities):**

* **`ThreadSafeMatch(const QualifiedName& a, const QualifiedName& b)` 和 `ThreadSafeMatch(const String& local_name, const QualifiedName& q_name)`:**
    * **功能:**  以线程安全的方式比较限定名（`QualifiedName`）或字符串与限定名的本地部分。
    * **与 HTML 的关系:** 用于比较 HTML 元素的标签名和属性名。线程安全特性在多线程的渲染引擎中非常重要。
* **`AttemptStaticStringCreation(...)`:**
    * **功能:**  尝试创建一个静态字符串（如果可能）。静态字符串是在编译时就创建的，可以提高性能，避免重复分配内存。
    * **与 HTML 的关系:**  用于优化常见 HTML 标签名和属性名的创建。

**与 JavaScript 和 CSS 的关系:**

* **JavaScript:**  HTML 解析的结果会构建 DOM 树，而 JavaScript 主要操作 DOM 树。因此，`html_parser_idioms.cc` 中处理的数字、字符串和编码等信息最终会影响到 JavaScript 如何访问和操作 HTML 元素及其属性。例如，如果 HTML 属性 `width=" 100 "` 被解析为整数 `100`，那么 JavaScript 通过 `element.getAttribute('width')` 获取到的值也会是 `"100"` (字符串形式，但数值已正确解析)。
* **CSS:**  虽然这个文件主要关注 HTML 解析，但其中一些函数，如数字解析和字符串处理，也可能间接地用于处理 CSS 相关的 HTML 属性，例如 `style` 属性中的内联样式值。 然而，Blink 引擎有专门的 CSS 解析器来处理更复杂的 CSS 语法。

总而言之，`html_parser_idioms.cc` 提供了一组核心的、可重用的工具函数，用于处理 HTML 解析过程中常见的模式，包括字符串清理、数字解析、字符编码处理以及线程安全的比较操作。 它的存在简化了 HTML 解析器的开发，并确保了对 HTML 规范的正确实现。

Prompt: 
```
这是目录为blink/renderer/core/html/parser/html_parser_idioms.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2010 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"

#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/character_visitor.h"
#include "third_party/blink/renderer/platform/wtf/text/parsing_utilities.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"
#include "third_party/blink/renderer/platform/wtf/text/string_to_number.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding.h"

#include <limits>

namespace blink {

String StripLeadingAndTrailingHTMLSpaces(const String& string) {
  unsigned length = string.length();

  if (!length)
    return string.IsNull() ? string : g_empty_atom.GetString();

  return WTF::VisitCharacters(string, [&](auto chars) {
    unsigned num_leading_spaces = 0;
    unsigned num_trailing_spaces = 0;

    for (; num_leading_spaces < length; ++num_leading_spaces) {
      if (IsNotHTMLSpace(chars[num_leading_spaces]))
        break;
    }

    if (num_leading_spaces == length)
      return string.IsNull() ? string : g_empty_atom.GetString();

    for (; num_trailing_spaces < length; ++num_trailing_spaces) {
      if (IsNotHTMLSpace(chars[length - num_trailing_spaces - 1]))
        break;
    }

    DCHECK_LT(num_leading_spaces + num_trailing_spaces, length);

    if (!(num_leading_spaces | num_trailing_spaces))
      return string;

    return string.Substring(num_leading_spaces, length - (num_leading_spaces +
                                                          num_trailing_spaces));
  });
}

// TODO(iclelland): Consider refactoring this into a general
// String::Split(predicate) method
Vector<String> SplitOnASCIIWhitespace(const String& input) {
  Vector<String> output;
  unsigned length = input.length();
  if (!length) {
    return output;
  }
  WTF::VisitCharacters(input, [&](auto chars) {
    const auto* cursor = chars.data();
    using CharacterType = std::decay_t<decltype(*cursor)>;
    const CharacterType* string_start = cursor;
    const CharacterType* string_end = cursor + chars.size();
    SkipWhile<CharacterType, IsHTMLSpace>(cursor, string_end);
    while (cursor < string_end) {
      const CharacterType* token_start = cursor;
      SkipUntil<CharacterType, IsHTMLSpace>(cursor, string_end);
      output.push_back(input.Substring((unsigned)(token_start - string_start),
                                       (unsigned)(cursor - token_start)));
      SkipWhile<CharacterType, IsHTMLSpace>(cursor, string_end);
    }
  });
  return output;
}

String SerializeForNumberType(const Decimal& number) {
  if (number.IsZero()) {
    // Decimal::toString appends exponent, e.g. "0e-18"
    return number.IsNegative() ? "-0" : "0";
  }
  return number.ToString();
}

String SerializeForNumberType(double number) {
  // According to HTML5, "the best representation of the number n as a floating
  // point number" is a string produced by applying ToString() to n.
  return String::NumberToStringECMAScript(number);
}

Decimal ParseToDecimalForNumberType(const String& string,
                                    const Decimal& fallback_value) {
  // http://www.whatwg.org/specs/web-apps/current-work/#floating-point-numbers
  // and parseToDoubleForNumberType String::toDouble() accepts leading + and
  // whitespace characters, which are not valid here.
  const UChar first_character = string[0];
  if (first_character != '-' && first_character != '.' &&
      !IsASCIIDigit(first_character))
    return fallback_value;

  const Decimal value = Decimal::FromString(string);
  if (!value.IsFinite())
    return fallback_value;

  // Numbers are considered finite IEEE 754 Double-precision floating point
  // values.
  const Decimal double_max =
      Decimal::FromDouble(std::numeric_limits<double>::max());
  if (value < -double_max || value > double_max)
    return fallback_value;

  // We return +0 for -0 case.
  return value.IsZero() ? Decimal(0) : value;
}

static double CheckDoubleValue(double value,
                               bool valid,
                               double fallback_value) {
  if (!valid)
    return fallback_value;

  // NaN and infinity are considered valid by String::toDouble, but not valid
  // here.
  if (!std::isfinite(value))
    return fallback_value;

  // Numbers are considered finite IEEE 754 Double-precision floating point
  // values.
  if (-std::numeric_limits<double>::max() > value ||
      value > std::numeric_limits<double>::max())
    return fallback_value;

  // The following expression converts -0 to +0.
  return value ? value : 0;
}

double ParseToDoubleForNumberType(const String& string, double fallback_value) {
  // http://www.whatwg.org/specs/web-apps/current-work/#floating-point-numbers
  // String::toDouble() accepts leading + and whitespace characters, which are
  // not valid here.
  UChar first_character = string[0];
  if (first_character != '-' && first_character != '.' &&
      !IsASCIIDigit(first_character))
    return fallback_value;
  if (string.EndsWith('.'))
    return fallback_value;

  bool valid = false;
  double value = string.ToDouble(&valid);
  return CheckDoubleValue(value, valid, fallback_value);
}

template <typename CharacterType>
static bool ParseHTMLIntegerInternal(const CharacterType* position,
                                     const CharacterType* end,
                                     int& value) {}

// http://www.whatwg.org/specs/web-apps/current-work/#rules-for-parsing-integers
bool ParseHTMLInteger(const String& input, int& value) {
  // Step 1
  // Step 2
  unsigned length = input.length();
  if (length == 0)
    return false;

  return WTF::VisitCharacters(input, [&](auto chars) {
    const auto* position = chars.data();
    using CharacterType = std::decay_t<decltype(*position)>;
    const auto* end = position + chars.size();

    // Step 4
    SkipWhile<CharacterType, IsHTMLSpace<CharacterType>>(position, end);

    // Step 5
    if (position == end) {
      return false;
    }
    DCHECK_LT(position, end);

    bool ok;
    constexpr auto kOptions = WTF::NumberParsingOptions()
                                  .SetAcceptTrailingGarbage()
                                  .SetAcceptLeadingPlus();
    int wtf_value =
        CharactersToInt(base::span<const CharacterType>(
                            position, static_cast<size_t>(end - position)),
                        kOptions, &ok);
    if (ok) {
      value = wtf_value;
    }
    return ok;
  });
}

static WTF::NumberParsingResult ParseHTMLNonNegativeIntegerInternal(
    const String& input,
    unsigned& value) {
  unsigned length = input.length();
  if (length == 0)
    return WTF::NumberParsingResult::kError;

  return WTF::VisitCharacters(
      input, [&](auto chars) {
        const auto* position = chars.data();
        using CharacterType = std::decay_t<decltype(*position)>;
        const auto* end = position + chars.size();

        // This function is an implementation of the following algorithm:
        // https://html.spec.whatwg.org/C/#rules-for-parsing-non-negative-integers
        // However, in order to support integers >= 2^31, we fold [1] into this.
        // 'Step N' in the following comments refers to [1].
        //
        // [1]
        // https://html.spec.whatwg.org/C/#rules-for-parsing-integers

        // Step 4: Skip whitespace.
        SkipWhile<CharacterType, IsHTMLSpace<CharacterType>>(position, end);

        // Step 5: If position is past the end of input, return an error.
        if (position == end)
          return WTF::NumberParsingResult::kError;
        DCHECK_LT(position, end);

        WTF::NumberParsingResult result;
        constexpr auto kOptions = WTF::NumberParsingOptions()
                                      .SetAcceptTrailingGarbage()
                                      .SetAcceptLeadingPlus()
                                      .SetAcceptMinusZeroForUnsigned();
        unsigned wtf_value = CharactersToUInt(
            {position, static_cast<size_t>(end - position)}, kOptions, &result);
        if (result == WTF::NumberParsingResult::kSuccess)
          value = wtf_value;
        return result;
      });
}

// https://html.spec.whatwg.org/C/#rules-for-parsing-non-negative-integers
bool ParseHTMLNonNegativeInteger(const String& input, unsigned& value) {
  return ParseHTMLNonNegativeIntegerInternal(input, value) ==
         WTF::NumberParsingResult::kSuccess;
}

bool ParseHTMLClampedNonNegativeInteger(const String& input,
                                        unsigned min,
                                        unsigned max,
                                        unsigned& value) {
  unsigned parsed_value;
  switch (ParseHTMLNonNegativeIntegerInternal(input, parsed_value)) {
    case WTF::NumberParsingResult::kError:
      return false;
    case WTF::NumberParsingResult::kOverflowMin:
      NOTREACHED() << input;
    case WTF::NumberParsingResult::kOverflowMax:
      value = max;
      return true;
    case WTF::NumberParsingResult::kSuccess:
      value = std::max(min, std::min(parsed_value, max));
      return true;
  }
  return false;
}

template <typename CharacterType>
static bool IsSpaceOrDelimiter(CharacterType c) {
  return IsHTMLSpace(c) || c == ',' || c == ';';
}

template <typename CharacterType>
static bool IsNotSpaceDelimiterOrNumberStart(CharacterType c) {
  return !(IsSpaceOrDelimiter(c) || IsASCIIDigit(c) || c == '.' || c == '-');
}

template <typename CharacterType>
static Vector<double> ParseHTMLListOfFloatingPointNumbersInternal(
    const CharacterType* position,
    const CharacterType* end) {
  Vector<double> numbers;
  return numbers;
}

// https://html.spec.whatwg.org/C/#rules-for-parsing-a-list-of-floating-point-numbers
Vector<double> ParseHTMLListOfFloatingPointNumbers(const String& input) {
  Vector<double> numbers;
  unsigned length = input.length();
  if (!length)
    return numbers;

  WTF::VisitCharacters(input, [&](auto chars) {
    const auto* position = chars.data();
    using CharacterType = std::decay_t<decltype(*position)>;
    const auto* end = position + chars.size();

    SkipWhile<CharacterType, IsSpaceOrDelimiter>(position, end);

    while (position < end) {
      SkipWhile<CharacterType, IsNotSpaceDelimiterOrNumberStart>(position, end);

      const CharacterType* unparsed_number_start = position;
      SkipUntil<CharacterType, IsSpaceOrDelimiter>(position, end);

      size_t parsed_length = 0;
      double number = CharactersToDouble(
          {unparsed_number_start,
           static_cast<size_t>(position - unparsed_number_start)},
          parsed_length);
      numbers.push_back(CheckDoubleValue(number, parsed_length != 0, 0));

      SkipWhile<CharacterType, IsSpaceOrDelimiter>(position, end);
    }
  });
  return numbers;
}

static const char kCharsetString[] = "charset";
static const size_t kCharsetLength = sizeof("charset") - 1;

// https://html.spec.whatwg.org/C/#extracting-character-encodings-from-meta-elements
String ExtractCharset(const String& value) {
  wtf_size_t pos = 0;
  unsigned length = value.length();

  while (pos < length) {
    pos = value.FindIgnoringASCIICase(kCharsetString, pos);
    if (pos == kNotFound)
      break;

    pos += kCharsetLength;

    // Skip whitespace.
    while (pos < length && value[pos] <= ' ')
      ++pos;

    if (value[pos] != '=')
      continue;

    ++pos;

    while (pos < length && value[pos] <= ' ')
      ++pos;

    char quote_mark = 0;
    if (pos < length && (value[pos] == '"' || value[pos] == '\'')) {
      quote_mark = static_cast<char>(value[pos++]);
      DCHECK(!(quote_mark & 0x80));
    }

    if (pos == length)
      break;

    unsigned end = pos;
    while (end < length &&
           ((quote_mark && value[end] != quote_mark) ||
            (!quote_mark && value[end] > ' ' && value[end] != '"' &&
             value[end] != '\'' && value[end] != ';')))
      ++end;

    if (quote_mark && (end == length))
      break;  // Close quote not found.

    return value.Substring(pos, end - pos);
  }

  return "";
}

enum class MetaAttribute {
  kNone,
  kCharset,
  kPragma,
};

WTF::TextEncoding EncodingFromMetaAttributes(
    const HTMLAttributeList& attributes) {
  bool got_pragma = false;
  bool has_charset = false;
  MetaAttribute mode = MetaAttribute::kNone;
  String charset;

  for (const auto& html_attribute : attributes) {
    const String& attribute_name = html_attribute.first;
    const AtomicString& attribute_value = AtomicString(html_attribute.second);

    if (ThreadSafeMatch(attribute_name, html_names::kHttpEquivAttr)) {
      if (EqualIgnoringASCIICase(attribute_value, "content-type"))
        got_pragma = true;
    } else if (ThreadSafeMatch(attribute_name, html_names::kCharsetAttr)) {
      has_charset = true;
      charset = attribute_value;
      mode = MetaAttribute::kCharset;
    } else if (!has_charset &&
               ThreadSafeMatch(attribute_name, html_names::kContentAttr)) {
      charset = ExtractCharset(attribute_value);
      if (charset.length())
        mode = MetaAttribute::kPragma;
    }
  }

  if (mode == MetaAttribute::kCharset ||
      (mode == MetaAttribute::kPragma && got_pragma))
    return WTF::TextEncoding(StripLeadingAndTrailingHTMLSpaces(charset));

  return WTF::TextEncoding();
}

static bool ThreadSafeEqual(const StringImpl* a, const StringImpl* b) {
  if (a == b)
    return true;
  if (a->GetHash() != b->GetHash())
    return false;
  return EqualNonNull(a, b);
}

bool ThreadSafeMatch(const QualifiedName& a, const QualifiedName& b) {
  return ThreadSafeEqual(a.LocalName().Impl(), b.LocalName().Impl());
}

bool ThreadSafeMatch(const String& local_name, const QualifiedName& q_name) {
  return ThreadSafeEqual(local_name.Impl(), q_name.LocalName().Impl());
}

template <typename CharType>
inline StringImpl* FindStringIfStatic(base::span<const CharType> characters) {
  // We don't need to try hashing if we know the string is too long.
  if (characters.size() > StringImpl::HighestStaticStringLength()) {
    return nullptr;
  }
  // ComputeHashAndMaskTop8Bits is the function StringImpl::Hash() uses.
  unsigned hash = StringHasher::ComputeHashAndMaskTop8Bits(
      reinterpret_cast<const char*>(characters.data()), characters.size());
  const WTF::StaticStringsTable& table = StringImpl::AllStaticStrings();
  DCHECK(!table.empty());

  WTF::StaticStringsTable::const_iterator it = table.find(hash);
  if (it == table.end())
    return nullptr;
  // It's possible to have hash collisions between arbitrary strings and known
  // identifiers (e.g. "bvvfg" collides with "script"). However ASSERTs in
  // StringImpl::createStatic guard against there ever being collisions between
  // static strings.
  if (!Equal(it->value, characters)) {
    return nullptr;
  }
  return it->value;
}

String AttemptStaticStringCreation(base::span<const LChar> characters) {
  String string(FindStringIfStatic(characters));
  if (string.Impl())
    return string;
  return String(characters);
}

String AttemptStaticStringCreation(base::span<const UChar> characters,
                                   CharacterWidth width) {
  String string(FindStringIfStatic(characters));
  if (string.Impl())
    return string;
  if (width == kLikely8Bit)
    string = StringImpl::Create8BitIfPossible(characters);
  else if (width == kForce8Bit)
    string = String::Make8BitFrom16BitSource(characters);
  else
    string = String(characters);

  return string;
}

}  // namespace blink

"""

```